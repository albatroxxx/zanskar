// SPDX-License-Identifier: Apache-2.0

package recording

// S3Storage keeps recordings in an S3 or S3-compatible bucket.
//
// A recording is appended to for the whole life of a session while S3
// objects are immutable, so each recording is spooled to a private temp file
// on local disk and uploaded when it is closed. Consequences: the spool
// directory must live on local disk with room for every concurrent session,
// and a gateway crash between the last write and the upload loses that
// recording (the session row still exists; its recording will show no
// finished_at). Objects are written with server-side encryption, KMS when a
// key id is configured and AES256 otherwise; integrity is the SHA-256 the
// recordings table already keeps.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// s3API is the slice of the S3 client this backend uses, kept narrow so
// tests can fake it without a network.
type s3API interface {
	PutObject(ctx context.Context, in *s3.PutObjectInput, opts ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(ctx context.Context, in *s3.GetObjectInput, opts ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	DeleteObject(ctx context.Context, in *s3.DeleteObjectInput, opts ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
}

// S3Options configures NewS3Storage.
type S3Options struct {
	Bucket string
	Prefix string // key prefix, default "recordings/"
	Region string // empty: the SDK's normal region resolution
	// Endpoint targets an S3-compatible service (MinIO, Ceph); path-style
	// addressing is enabled when it is set.
	Endpoint string
	// KMSKeyID selects aws:kms encryption with that key; empty uses AES256.
	KMSKeyID string
	// SpoolDir holds in-progress recordings; default os.TempDir()/zanskar-spool.
	SpoolDir string
}

// S3Storage implements Storage over a bucket.
type S3Storage struct {
	Bucket   string
	Prefix   string
	SpoolDir string
	KMSKeyID string
	client   s3API
}

// NewS3Storage builds the backend with the gateway's own AWS credentials
// (instance profile, IRSA, environment or a mounted profile).
func NewS3Storage(ctx context.Context, o S3Options) (*S3Storage, error) {
	if o.Bucket == "" {
		return nil, errors.New("recording: s3 bucket is required")
	}
	var loadOpts []func(*awsconfig.LoadOptions) error
	if o.Region != "" {
		loadOpts = append(loadOpts, awsconfig.WithRegion(o.Region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("recording: aws config: %w", err)
	}
	client := s3.NewFromConfig(cfg, func(so *s3.Options) {
		if o.Endpoint != "" {
			so.BaseEndpoint = aws.String(o.Endpoint)
			so.UsePathStyle = true
		}
	})
	return newS3Storage(client, o), nil
}

func newS3Storage(client s3API, o S3Options) *S3Storage {
	prefix := o.Prefix
	if prefix == "" {
		prefix = "recordings/"
	}
	prefix = strings.TrimPrefix(prefix, "/")
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	spool := o.SpoolDir
	if spool == "" {
		spool = filepath.Join(os.TempDir(), "zanskar-spool")
	}
	return &S3Storage{Bucket: o.Bucket, Prefix: prefix, SpoolDir: spool, KMSKeyID: o.KMSKeyID, client: client}
}

// Create implements Storage: it opens a spool file now and uploads on Close.
func (s *S3Storage) Create(_ context.Context, name string) (io.WriteCloser, string, error) {
	if strings.ContainsAny(name, `/\`) || name == "" || name == "." || name == ".." {
		return nil, "", errors.New("recording: bad name")
	}
	if err := os.MkdirAll(s.SpoolDir, 0o700); err != nil {
		return nil, "", err
	}
	f, err := os.CreateTemp(s.SpoolDir, "rec-*")
	if err != nil {
		return nil, "", err
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return nil, "", err
	}
	key := s.Prefix + name
	return &s3Spool{f: f, storage: s, key: key, contentType: contentTypeFor(name)}, "s3://" + s.Bucket + "/" + key, nil
}

// Open implements Storage. Only URIs inside this bucket and prefix are read.
func (s *S3Storage) Open(ctx context.Context, uri string) (io.ReadCloser, error) {
	want := "s3://" + s.Bucket + "/" + s.Prefix
	if !strings.HasPrefix(uri, want) {
		return nil, errors.New("recording: uri outside the configured bucket and prefix")
	}
	key := strings.TrimPrefix(uri, "s3://"+s.Bucket+"/")
	if path.Clean("/"+key) != "/"+key || strings.Contains(key, "..") {
		return nil, errors.New("recording: bad object key")
	}
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(s.Bucket), Key: aws.String(key)})
	if err != nil {
		return nil, fmt.Errorf("recording: get object: %w", err)
	}
	return out.Body, nil
}

// Delete implements Storage. Only objects inside this bucket and prefix are
// removed; S3 treats deleting an absent key as success, so sweeps are idempotent.
func (s *S3Storage) Delete(ctx context.Context, uri string) error {
	want := "s3://" + s.Bucket + "/" + s.Prefix
	if !strings.HasPrefix(uri, want) {
		return errors.New("recording: uri outside the configured bucket and prefix")
	}
	key := strings.TrimPrefix(uri, "s3://"+s.Bucket+"/")
	if path.Clean("/"+key) != "/"+key || strings.Contains(key, "..") {
		return errors.New("recording: bad object key")
	}
	if _, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(s.Bucket), Key: aws.String(key)}); err != nil {
		return fmt.Errorf("recording: delete object: %w", err)
	}
	return nil
}

// s3Spool is the WriteCloser handed to the recorder.
type s3Spool struct {
	f           *os.File
	storage     *S3Storage
	key         string
	contentType string
	closed      bool
}

func (w *s3Spool) Write(p []byte) (int, error) { return w.f.Write(p) }

// Close flushes the spool file, uploads it, and removes it. The upload
// error is returned so the caller records the failure against the session.
func (w *s3Spool) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	defer func() { _ = os.Remove(w.f.Name()) }()
	if err := w.f.Sync(); err != nil {
		_ = w.f.Close()
		return err
	}
	if _, err := w.f.Seek(0, io.SeekStart); err != nil {
		_ = w.f.Close()
		return err
	}
	info, err := w.f.Stat()
	if err != nil {
		_ = w.f.Close()
		return err
	}
	in := &s3.PutObjectInput{
		Bucket:        aws.String(w.storage.Bucket),
		Key:           aws.String(w.key),
		Body:          w.f,
		ContentLength: aws.Int64(info.Size()),
		ContentType:   aws.String(w.contentType),
	}
	if w.storage.KMSKeyID != "" {
		in.ServerSideEncryption = s3types.ServerSideEncryptionAwsKms
		in.SSEKMSKeyId = aws.String(w.storage.KMSKeyID)
	} else {
		in.ServerSideEncryption = s3types.ServerSideEncryptionAes256
	}
	// The spool is uploaded after the session ended, so its lifetime is not
	// tied to the request context.
	_, putErr := w.storage.client.PutObject(context.Background(), in)
	closeErr := w.f.Close()
	if putErr != nil {
		return fmt.Errorf("recording: upload %s: %w", w.key, putErr)
	}
	return closeErr
}

func contentTypeFor(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".cast":
		return "application/x-asciicast"
	default:
		return "application/octet-stream"
	}
}

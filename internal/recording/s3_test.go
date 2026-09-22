// SPDX-License-Identifier: Apache-2.0

package recording

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type fakeObject struct {
	body        []byte
	contentType string
	sse         s3types.ServerSideEncryption
	kmsKey      string
	length      int64
}

type fakeS3 struct {
	mu      sync.Mutex
	objects map[string]fakeObject // bucket/key
	putErr  error
}

func (f *fakeS3) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	if f.putErr != nil {
		return nil, f.putErr
	}
	body, err := io.ReadAll(in.Body)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.objects == nil {
		f.objects = map[string]fakeObject{}
	}
	f.objects[aws.ToString(in.Bucket)+"/"+aws.ToString(in.Key)] = fakeObject{
		body: body, contentType: aws.ToString(in.ContentType), sse: in.ServerSideEncryption, kmsKey: aws.ToString(in.SSEKMSKeyId), length: aws.ToInt64(in.ContentLength),
	}
	return &s3.PutObjectOutput{}, nil
}

func (f *fakeS3) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	o, ok := f.objects[aws.ToString(in.Bucket)+"/"+aws.ToString(in.Key)]
	if !ok {
		return nil, errors.New("NoSuchKey")
	}
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(o.body))}, nil
}

func (f *fakeS3) DeleteObject(_ context.Context, in *s3.DeleteObjectInput, _ ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.objects, aws.ToString(in.Bucket)+"/"+aws.ToString(in.Key))
	return &s3.DeleteObjectOutput{}, nil
}

func TestS3StorageRoundTrip(t *testing.T) {
	ctx := context.Background()
	fake := &fakeS3{}
	spool := t.TempDir()
	st := newS3Storage(fake, S3Options{Bucket: "recs", Prefix: "sessions", SpoolDir: spool, KMSKeyID: "arn:aws:kms:x:1:key/abc"})
	if st.Prefix != "sessions/" {
		t.Fatalf("prefix normalised wrong: %q", st.Prefix)
	}

	wc, uri, err := st.Create(ctx, "s1.cast")
	if err != nil {
		t.Fatal(err)
	}
	if uri != "s3://recs/sessions/s1.cast" {
		t.Fatalf("uri %q", uri)
	}
	spooled, _ := filepath.Glob(filepath.Join(spool, "rec-*"))
	if len(spooled) != 1 {
		t.Fatalf("expected one spool file, got %v", spooled)
	}
	if info, err := os.Stat(spooled[0]); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("spool perm: %v %v", info, err)
	}
	_, _ = wc.Write([]byte(`{"version":2}` + "\n"))
	_, _ = wc.Write([]byte(`[0.1,"o","hi"]` + "\n"))
	if err := wc.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := wc.Close(); err != nil {
		t.Fatal("double close must be harmless")
	}
	if left, _ := filepath.Glob(filepath.Join(spool, "rec-*")); len(left) != 0 {
		t.Fatalf("spool file not removed: %v", left)
	}
	obj, ok := fake.objects["recs/sessions/s1.cast"]
	want := `{"version":2}` + "\n" + `[0.1,"o","hi"]` + "\n"
	if !ok || string(obj.body) != want || obj.length != int64(len(want)) {
		t.Fatalf("uploaded object wrong: ok=%v %q", ok, obj.body)
	}
	if obj.contentType != "application/x-asciicast" || obj.sse != s3types.ServerSideEncryptionAwsKms || obj.kmsKey != "arn:aws:kms:x:1:key/abc" {
		t.Fatalf("headers: %+v", obj)
	}

	rc, err := st.Open(ctx, uri)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(rc)
	_ = rc.Close()
	if string(got) != want {
		t.Fatalf("read back %q", got)
	}

	// Desktop recordings default to octet-stream and AES256 without a key.
	plain := newS3Storage(fake, S3Options{Bucket: "recs", SpoolDir: spool})
	wc2, uri2, _ := plain.Create(ctx, "s2.guac")
	_, _ = wc2.Write([]byte("4.sync;"))
	_ = wc2.Close()
	if o := fake.objects["recs/recordings/s2.guac"]; o.contentType != "application/octet-stream" || o.sse != s3types.ServerSideEncryptionAes256 || uri2 != "s3://recs/recordings/s2.guac" {
		t.Fatalf("guac object: %+v uri=%s", o, uri2)
	}
}

func TestS3StorageGuards(t *testing.T) {
	ctx := context.Background()
	fake := &fakeS3{}
	st := newS3Storage(fake, S3Options{Bucket: "recs", SpoolDir: t.TempDir()})
	for _, bad := range []string{"", "..", "a/b", `a\b`} {
		if _, _, err := st.Create(ctx, bad); err == nil {
			t.Errorf("name %q accepted", bad)
		}
	}
	if _, err := st.Open(ctx, "s3://other/recordings/x.cast"); err == nil {
		t.Fatal("foreign bucket must be refused")
	}
	if _, err := st.Open(ctx, "s3://recs/elsewhere/x.cast"); err == nil {
		t.Fatal("foreign prefix must be refused")
	}
	if _, err := st.Open(ctx, "s3://recs/recordings/../secret"); err == nil {
		t.Fatal("traversal must be refused")
	}
	if _, err := st.Open(ctx, "s3://recs/recordings/missing.cast"); err == nil {
		t.Fatal("missing object must error")
	}
}

func TestS3StorageClosePropagatesUploadError(t *testing.T) {
	ctx := context.Background()
	fake := &fakeS3{putErr: errors.New("AccessDenied")}
	spool := t.TempDir()
	st := newS3Storage(fake, S3Options{Bucket: "recs", SpoolDir: spool})
	wc, _, err := st.Create(ctx, "s3.cast")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = wc.Write([]byte("data"))
	if err := wc.Close(); err == nil || !errors.Is(err, fake.putErr) {
		t.Fatalf("expected upload error, got %v", err)
	}
	if left, _ := filepath.Glob(filepath.Join(spool, "rec-*")); len(left) != 0 {
		t.Fatalf("spool file must be removed even on failure: %v", left)
	}
}

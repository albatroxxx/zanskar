// SPDX-License-Identifier: Apache-2.0

package recording

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync/atomic"
)

// Router is the Storage the gateway hands to sessions, the player and the
// retention sweeper. New recordings go to the S3 backend when one is set
// and to the local directory otherwise; reads and deletes follow the URI,
// so recordings made before a change of backend stay reachable. The S3
// backend is swapped in place (ADR 0020); a session that already started
// keeps the backend it opened its recording with.
type Router struct {
	Local Storage
	s3    atomic.Pointer[S3Storage]
}

// SetS3 makes s the backend for new recordings; nil means the local directory.
func (r *Router) SetS3(s *S3Storage) { r.s3.Store(s) }

// S3 returns the active S3 backend, or nil.
func (r *Router) S3() *S3Storage { return r.s3.Load() }

// Create implements Storage.
func (r *Router) Create(ctx context.Context, name string) (io.WriteCloser, string, error) {
	if s := r.s3.Load(); s != nil {
		return s.Create(ctx, name)
	}
	return r.Local.Create(ctx, name)
}

// Open implements Storage, by the URI's scheme.
func (r *Router) Open(ctx context.Context, uri string) (io.ReadCloser, error) {
	if strings.HasPrefix(uri, "s3://") {
		s := r.s3.Load()
		if s == nil {
			return nil, errors.New("recording: stored in S3 but no S3 storage is configured")
		}
		return s.Open(ctx, uri)
	}
	return r.Local.Open(ctx, uri)
}

// Delete implements Storage, by the URI's scheme.
func (r *Router) Delete(ctx context.Context, uri string) error {
	if strings.HasPrefix(uri, "s3://") {
		s := r.s3.Load()
		if s == nil {
			return errors.New("recording: stored in S3 but no S3 storage is configured")
		}
		return s.Delete(ctx, uri)
	}
	return r.Local.Delete(ctx, uri)
}

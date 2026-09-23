// SPDX-License-Identifier: Apache-2.0

package sshgw

import (
	"errors"
	"os"
	"path"
	"sort"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// FileEntry is one directory entry as reported to the browser.
type FileEntry struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	Dir   bool   `json:"dir"`
	Size  int64  `json:"size"`
	Mode  string `json:"mode"`
	MTime int64  `json:"mtime"` // unix seconds
}

// SFTP is an SFTP subsystem opened over an existing target SSH connection
// (ADR 0016). It multiplexes a new channel on the connection Zanskar already
// holds for the terminal session, so it needs no second dial or credential.
// Open one, use it, Close it. The target account's own filesystem permissions
// are the boundary; Zanskar mediates and audits but never widens them.
type SFTP struct{ c *sftp.Client }

// OpenSFTP starts the SFTP subsystem on client. It fails if the target's SSH
// server does not offer the subsystem.
func OpenSFTP(client *ssh.Client) (*SFTP, error) {
	c, err := sftp.NewClient(client)
	if err != nil {
		return nil, err
	}
	return &SFTP{c: c}, nil
}

// Close releases the SFTP channel.
func (s *SFTP) Close() error { return s.c.Close() }

// Home is the login user's working directory, where browsing starts.
func (s *SFTP) Home() string {
	if wd, err := s.c.Getwd(); err == nil && wd != "" {
		return wd
	}
	return "."
}

// List returns dir's entries, directories first then by name.
func (s *SFTP) List(dir string) ([]FileEntry, error) {
	if dir == "" {
		dir = s.Home()
	}
	infos, err := s.c.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := make([]FileEntry, 0, len(infos))
	for _, fi := range infos {
		out = append(out, FileEntry{
			Name: fi.Name(), Path: path.Join(dir, fi.Name()), Dir: fi.IsDir(),
			Size: fi.Size(), Mode: fi.Mode().String(), MTime: fi.ModTime().Unix(),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Dir != out[j].Dir {
			return out[i].Dir
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// Open opens a remote file for download; the caller closes it.
func (s *SFTP) Open(p string) (*sftp.File, os.FileInfo, error) {
	fi, err := s.c.Stat(p)
	if err != nil {
		return nil, nil, err
	}
	if fi.IsDir() {
		return nil, nil, errors.New("sshgw: path is a directory")
	}
	f, err := s.c.Open(p)
	if err != nil {
		return nil, nil, err
	}
	return f, fi, nil
}

// Create creates or truncates a remote file for upload; the caller closes it.
func (s *SFTP) Create(p string) (*sftp.File, error) {
	return s.c.Create(p)
}

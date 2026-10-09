// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/albatroxxx/zanskar/internal/keyring"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/user"
)

// tarEntry is one entry of a hand-built archive.
type tarEntry struct {
	name, body, link string
	typ              byte
	short            bool // declare more bytes than are written (a truncated archive)
}

// craftArchive writes a tar.gz from entries, the way an attacker or a broken
// copy could, without going through writeTarGz.
func craftArchive(t *testing.T, entries ...tarEntry) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	truncated := false
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		hdr := &tar.Header{Name: e.name, Mode: 0o600, Typeflag: typ, Linkname: e.link}
		if typ == tar.TypeDir {
			hdr.Mode = 0o700
		}
		if typ == tar.TypeReg {
			hdr.Size = int64(len(e.body))
			if e.short {
				hdr.Size += 1000
			}
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
		if e.short {
			truncated = true
			break
		}
	}
	if !truncated {
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
	} else {
		_ = tw.Flush() // reports the missing bytes; the archive stays truncated
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "crafted.tar.gz")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func manifestJSON(t *testing.T, m backupManifest) string {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestBackupRecordingsElsewhere: with recordings in S3 the archive notes it
// and copies nothing (even if a local directory exists); with no local
// directory the archive says none were included. Restore repeats the S3 note.
func TestBackupRecordingsElsewhere(t *testing.T) {
	g := newCLIGateway(t, true)
	if err := os.MkdirAll(g.recDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(g.recDir, "spooled.cast"), []byte("spool"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("s3", func(t *testing.T) {
		t.Setenv("ZANSKAR_RECORDINGS_S3_BUCKET", "zanskar-recordings")
		t.Setenv("ZANSKAR_RECORDINGS_S3_REGION", "us-east-1")
		archive := filepath.Join(t.TempDir(), "s3.tar.gz")
		out, _, err := output(t, func() error { return runBackup([]string{"-out", archive}) })
		if err != nil || !strings.Contains(out, "Recordings are in S3 and were not copied") || !strings.Contains(out, "NOT in this archive") {
			t.Fatalf("backup: %v\n%s", err, out)
		}
		files := readTarGz(t, archive)
		for name := range files {
			if strings.HasPrefix(name, "recordings/") {
				t.Fatalf("an S3 deployment's archive must not carry local recordings: %s", name)
			}
		}
		var man backupManifest
		if err := json.Unmarshal(files["manifest.json"], &man); err != nil {
			t.Fatal(err)
		}
		if man.RecordingsBackend != "s3" || man.RecordingsIncluded {
			t.Fatalf("manifest %+v", man)
		}
		if info, err := os.Stat(archive); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("archive must be owner-only: %v %v", info, err)
		}

		out, _, err = output(t, func() error { return runRestore([]string{"-in", archive, "-force"}) })
		if err != nil || !strings.Contains(out, "Recordings live in S3") || strings.Contains(out, "recordings to") {
			t.Fatalf("restore: %v\n%s", err, out)
		}
	})

	t.Run("no recordings directory", func(t *testing.T) {
		t.Setenv("ZANSKAR_RECORDINGS_DIR", filepath.Join(g.dir, "no-such-dir"))
		archive := filepath.Join(t.TempDir(), "none.tar.gz")
		out, _, err := output(t, func() error { return runBackup([]string{"-out", archive}) })
		if err != nil || !strings.Contains(out, "No local recordings directory was found") {
			t.Fatalf("backup: %v\n%s", err, out)
		}
		var man backupManifest
		_ = json.Unmarshal(readTarGz(t, archive)["manifest.json"], &man)
		if man.RecordingsBackend != "none" || man.RecordingsIncluded {
			t.Fatalf("manifest %+v", man)
		}
	})
}

// TestBackupDefaultOutPath: without -out the archive lands in the current
// directory under a timestamped name.
func TestBackupDefaultOutPath(t *testing.T) {
	newCLIGateway(t, true)
	cwd := t.TempDir()
	t.Chdir(cwd)
	out, _, err := output(t, func() error { return runBackup(nil) })
	if err != nil {
		t.Fatalf("backup: %v", err)
	}
	matches, _ := filepath.Glob(filepath.Join(cwd, "zanskar-backup-*.tar.gz"))
	if len(matches) != 1 || !strings.Contains(out, "Wrote "+filepath.Base(matches[0])) {
		t.Fatalf("archives %v, output %q", matches, out)
	}
	if _, ok := readTarGz(t, matches[0])["db/zanskar.db"]; !ok {
		t.Fatal("the archive must hold the database snapshot")
	}
}

// TestBackupRefusals: backup refuses bad flags, an in-memory database, a
// missing master key, a database that cannot be opened and an
// archive path it cannot create, leaving no archive behind.
func TestBackupRefusals(t *testing.T) {
	g := newCLIGateway(t, true)
	archive := filepath.Join(g.dir, "out.tar.gz")

	if _, _, err := output(t, func() error { return runBackup([]string{"-bogus"}) }); err == nil {
		t.Error("an unknown flag must fail")
	}
	t.Run("in-memory database", func(t *testing.T) {
		t.Setenv("ZANSKAR_DB_DSN", "file::memory:?_pragma=foreign_keys(1)")
		if _, _, err := output(t, func() error { return runBackup([]string{"-out", archive}) }); err == nil || !strings.Contains(err.Error(), "in-memory") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("no master key", func(t *testing.T) {
		t.Setenv("ZANSKAR_MASTER_KEY", "")
		if _, _, err := output(t, func() error { return runBackup([]string{"-out", archive}) }); err == nil || !strings.Contains(err.Error(), "ZANSKAR_MASTER_KEY") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("database directory missing", func(t *testing.T) {
		t.Setenv("ZANSKAR_DB_DSN", "file:"+filepath.Join(g.dir, "nowhere", "z.db"))
		if _, _, err := output(t, func() error { return runBackup([]string{"-out", archive}) }); err == nil {
			t.Fatal("a database that cannot be opened must fail the backup")
		}
	})
	t.Run("archive directory missing", func(t *testing.T) {
		bad := filepath.Join(g.dir, "no-such-dir", "out.tar.gz")
		out, _, err := output(t, func() error { return runBackup([]string{"-out", bad}) })
		if err == nil || strings.Contains(out, "Wrote") {
			t.Fatalf("got %v, %q", err, out)
		}
	})
	if _, err := os.Stat(archive); err == nil {
		t.Fatal("no refused backup may leave an archive")
	}
}

// TestRestoreRefusesBadArchives: restore refuses an archive it cannot read, a
// non-gzip file, one without a manifest or with a corrupt one, one without a
// database snapshot and a truncated one, and in every case leaves the existing
// database in place even with --force.
func TestRestoreRefusesBadArchives(t *testing.T) {
	g := newCLIGateway(t, true)
	g.with(t, func(ctx context.Context, db *store.DB, _ *keyring.Ring) {
		u := &user.User{Username: "keeper", DisplayName: "Keeper", Roles: []user.Role{user.RoleUser}}
		if err := user.NewRepo(db).Create(ctx, u); err != nil {
			t.Fatal(err)
		}
	})
	man := manifestJSON(t, backupManifest{DBDriver: "sqlite", KeyFingerprint: keyFingerprint(g.key), RecordingsBackend: "none"})
	notGzip := filepath.Join(t.TempDir(), "plain.tar.gz")
	if err := os.WriteFile(notGzip, []byte("this is not a gzip stream"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, archive, want string
	}{
		{"missing archive", filepath.Join(g.dir, "absent.tar.gz"), "no such file"},
		{"not gzip", notGzip, "gzip"},
		{"no manifest", craftArchive(t, tarEntry{name: "db/zanskar.db", body: "x"}), "read manifest"},
		{"corrupt manifest", craftArchive(t, tarEntry{name: "manifest.json", body: "{not json"}), "parse manifest"},
		{"no database", craftArchive(t, tarEntry{name: "manifest.json", body: man}), "no database snapshot"},
		{"truncated", craftArchive(t, tarEntry{name: "manifest.json", body: man}, tarEntry{name: "db/zanskar.db", body: "partial", short: true}), "unexpected EOF"},
		{"traversal", craftArchive(t, tarEntry{name: "manifest.json", body: man}, tarEntry{name: "db/../../zanskar.db", body: "evil"}), "escapes destination"},
		{"absolute path", craftArchive(t, tarEntry{name: "/etc/zanskar-evil", body: "evil"}), "escapes destination"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, _, err := output(t, func() error { return runRestore([]string{"-in", c.archive, "-force"}) })
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want an error mentioning %q, got %v", c.want, err)
			}
			if strings.Contains(out, "Restored") {
				t.Fatalf("a refused restore must not report success: %s", out)
			}
			g.with(t, func(ctx context.Context, db *store.DB, _ *keyring.Ring) {
				if _, err := user.NewRepo(db).GetByUsername(ctx, "keeper"); err != nil {
					t.Fatalf("the existing database must survive a refused restore: %v", err)
				}
			})
		})
	}
}

// TestRestoreConfigRefusals: restore needs a SQLite file database and the
// master key, and rejects unknown flags.
func TestRestoreConfigRefusals(t *testing.T) {
	g := newCLIGateway(t, false)
	archive := filepath.Join(g.dir, "any.tar.gz")
	if _, _, err := output(t, func() error { return runRestore([]string{"-bogus"}) }); err == nil {
		t.Error("an unknown flag must fail")
	}
	t.Run("postgres", func(t *testing.T) {
		t.Setenv("ZANSKAR_DB_DRIVER", "postgres")
		t.Setenv("ZANSKAR_DB_DSN", "postgres://zanskar@localhost/zanskar")
		if _, _, err := output(t, func() error { return runRestore([]string{"-in", archive}) }); err == nil || !strings.Contains(err.Error(), "SQLite database only") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("in-memory", func(t *testing.T) {
		t.Setenv("ZANSKAR_DB_DSN", "file::memory:")
		if _, _, err := output(t, func() error { return runRestore([]string{"-in", archive}) }); err == nil || !strings.Contains(err.Error(), "in-memory") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("no master key", func(t *testing.T) {
		t.Setenv("ZANSKAR_MASTER_KEY", "")
		if _, _, err := output(t, func() error { return runRestore([]string{"-in", archive}) }); err == nil || !strings.Contains(err.Error(), "ZANSKAR_MASTER_KEY") {
			t.Fatalf("got %v", err)
		}
	})
}

// TestRestoreFreshHost: restoring onto a host with no data directory creates
// it, places the database owner-only, drops stale WAL/SHM files that would
// otherwise override it, and skips symlink entries instead of following them.
func TestRestoreFreshHost(t *testing.T) {
	src := newCLIGateway(t, true)
	src.with(t, func(ctx context.Context, db *store.DB, _ *keyring.Ring) {
		u := &user.User{Username: "bob", DisplayName: "Bob", Roles: []user.Role{user.RoleUser}}
		if err := user.NewRepo(db).Create(ctx, u); err != nil {
			t.Fatal(err)
		}
	})
	archive := filepath.Join(t.TempDir(), "b.tar.gz")
	if _, _, err := output(t, func() error { return runBackup([]string{"-out", archive}) }); err != nil {
		t.Fatal(err)
	}

	fresh := t.TempDir()
	dbPath := filepath.Join(fresh, "var", "lib", "zanskar", "zanskar.db")
	t.Setenv("ZANSKAR_DB_DSN", "file:"+dbPath+"?_pragma=foreign_keys(1)")
	t.Setenv("ZANSKAR_RECORDINGS_DIR", filepath.Join(fresh, "recordings"))
	out, stderr, err := output(t, func() error { return runRestore([]string{"-in", archive}) })
	if err != nil || !strings.Contains(out, "Restored the database to "+dbPath) || !strings.Contains(out, "Start the service") || strings.Contains(stderr, "DIFFERENT") {
		t.Fatalf("restore: %v\n%s%s", err, out, stderr)
	}
	if info, err := os.Stat(dbPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("restored database must be owner-only: %v %v", info, err)
	}

	// A stale WAL beside an existing database is removed by a forced restore.
	for _, sfx := range []string{"-wal", "-shm"} {
		if err := os.WriteFile(dbPath+sfx, []byte("stale"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := output(t, func() error { return runRestore([]string{"-in", archive, "-force"}) }); err != nil {
		t.Fatal(err)
	}
	for _, sfx := range []string{"-wal", "-shm"} {
		if b, err := os.ReadFile(dbPath + sfx); err == nil && string(b) == "stale" { // #nosec G304 -- test temp file
			t.Fatalf("stale %s must be removed", sfx)
		}
	}
	db, err := store.Open(context.Background(), "sqlite", "file:"+dbPath+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := user.NewRepo(db).GetByUsername(context.Background(), "bob"); err != nil {
		t.Fatalf("restored database must hold bob: %v", err)
	}
	_ = db.Close()

	// A symlink entry is skipped, never created.
	dst := t.TempDir()
	link := craftArchive(t,
		tarEntry{name: "db", typ: tar.TypeDir},
		tarEntry{name: "db/escape", typ: tar.TypeSymlink, link: "/etc/passwd"},
		tarEntry{name: "db/ok.txt", body: "fine"},
	)
	if err := extractTarGz(link, dst); err != nil {
		t.Fatalf("extract: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dst, "db", "escape")); err == nil {
		t.Fatal("a symlink entry must not be created")
	}
	if b, err := os.ReadFile(filepath.Join(dst, "db", "ok.txt")); err != nil || string(b) != "fine" { // #nosec G304 -- test temp file
		t.Fatalf("regular entry next to it: %q %v", b, err)
	}
}

// TestWriteTarGzFailureKeepsOutPath: a backup that fails part way leaves the
// file at -out as it was, and no partial archive or temporary file behind.
func TestWriteTarGzFailureKeepsOutPath(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads unreadable files")
	}
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "a"), []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "unreadable"), []byte("b"), 0o000); err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()
	out := filepath.Join(outDir, "backup.tar.gz")
	if err := os.WriteFile(out, []byte("yesterday's archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeTarGz(src, out); err == nil {
		t.Fatal("a walk over an unreadable file must fail")
	}
	if got, _ := os.ReadFile(out); string(got) != "yesterday's archive" {
		t.Fatalf("a failed backup replaced -out: %q", got)
	}
	if entries, _ := os.ReadDir(outDir); len(entries) != 1 {
		t.Fatalf("a failed backup left files behind: %v", entries)
	}
}

// TestCopyBesideCleansUp: the restore's staging copy lands next to the
// destination, owner-only, and a failed copy leaves nothing behind.
func TestCopyBesideCleansUp(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(t.TempDir(), "snap.db")
	if err := os.WriteFile(src, []byte("snapshot"), 0o644); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "zanskar.db")
	tmp, err := copyBeside(src, dst, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(tmp) != dir {
		t.Fatalf("staging copy in %s, want beside the database in %s", filepath.Dir(tmp), dir)
	}
	if fi, _ := os.Stat(tmp); fi.Mode().Perm() != 0o600 {
		t.Fatalf("staging copy mode %v, want 0600", fi.Mode().Perm())
	}
	_ = os.Remove(tmp)
	if _, err := copyBeside(filepath.Join(dir, "missing"), dst, 0o600); err == nil {
		t.Fatal("copying a missing snapshot must fail")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("a failed copy left files behind: %v", entries)
	}
}

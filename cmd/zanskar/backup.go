// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/version"
)

// backupManifest describes a backup archive. The master key is never included;
// its fingerprint lets restore warn when the current key differs, which would
// leave stored credentials unreadable.
type backupManifest struct {
	Version            string    `json:"zanskar_version"`
	CreatedAt          time.Time `json:"created_at"`
	DBDriver           string    `json:"db_driver"`
	KeyFingerprint     string    `json:"key_fingerprint"`
	RecordingsIncluded bool      `json:"recordings_included"`
	RecordingsBackend  string    `json:"recordings_backend"` // local | s3 | none
}

// runBackup writes a consistent snapshot of the SQLite database and the local
// recordings to a tar.gz. PostgreSQL deployments use pg_dump instead.
func runBackup(args []string) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	out := fs.String("out", "", "archive path (default zanskar-backup-<timestamp>.tar.gz in the current directory)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(config.Options{RequireMasterKey: true})
	if err != nil {
		return err
	}
	if cfg.DBDriver != config.DriverSQLite {
		return errors.New("backup supports the SQLite database; for PostgreSQL use pg_dump for the database and back up the recordings store separately")
	}
	if _, err := sqliteFilePath(cfg.DBDSN); err != nil {
		return err // refuses an in-memory database
	}

	stage, err := os.MkdirTemp("", "zanskar-backup-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(stage) }()

	// A consistent database copy, even while the gateway is running: VACUUM INTO
	// reads a single transactional snapshot.
	ctx := context.Background()
	db, err := store.Open(ctx, cfg.DBDriver, cfg.DBDSN)
	if err != nil {
		return err
	}
	snap := filepath.Join(stage, "db", "zanskar.db")
	if err := os.MkdirAll(filepath.Dir(snap), 0o750); err != nil {
		_ = db.Close()
		return err
	}
	if _, err := db.ExecContext(ctx, "VACUUM INTO ?", snap); err != nil {
		_ = db.Close()
		return fmt.Errorf("backup: snapshot database: %w", err)
	}
	_ = db.Close()

	man := backupManifest{
		Version:           version.Version,
		CreatedAt:         time.Now().UTC(),
		DBDriver:          cfg.DBDriver,
		KeyFingerprint:    keyFingerprint(cfg.MasterKey),
		RecordingsBackend: "none",
	}
	switch {
	case cfg.RecordingsS3Bucket != "":
		// S3 is durable and lives outside the box; note it rather than copy it.
		man.RecordingsBackend = "s3"
	case dirExists(cfg.RecordingsDir):
		if err := copyTree(cfg.RecordingsDir, filepath.Join(stage, "recordings")); err != nil {
			return fmt.Errorf("backup: copy recordings: %w", err)
		}
		man.RecordingsIncluded = true
		man.RecordingsBackend = "local"
	}

	manBytes, err := json.MarshalIndent(man, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(stage, "manifest.json"), manBytes, 0o600); err != nil {
		return err
	}

	outPath := *out
	if outPath == "" {
		outPath = fmt.Sprintf("zanskar-backup-%s.tar.gz", time.Now().UTC().Format("20060102-150405"))
	}
	if err := writeTarGz(stage, outPath); err != nil {
		return err
	}
	fmt.Printf("Wrote %s\n", outPath)
	if man.RecordingsBackend == "s3" {
		fmt.Println("Recordings are in S3 and were not copied; they are backed up by the object store.")
	} else if !man.RecordingsIncluded {
		fmt.Println("No local recordings directory was found; none were included.")
	}
	fmt.Println("The master key is NOT in this archive. Back up ZANSKAR_MASTER_KEY separately;")
	fmt.Println("without the same key, a restored database's stored credentials are unreadable.")
	return nil
}

// runRestore restores a backup into the configured locations. It refuses to
// overwrite an existing database without --force, and warns when the archive was
// sealed with a different master key.
func runRestore(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	in := fs.String("in", "", "backup archive to restore (required)")
	force := fs.Bool("force", false, "overwrite an existing database (stop the service first)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" {
		return errors.New("restore: --in <archive> is required")
	}
	cfg, err := config.Load(config.Options{RequireMasterKey: true})
	if err != nil {
		return err
	}
	if cfg.DBDriver != config.DriverSQLite {
		return errors.New("restore supports the SQLite database only")
	}
	dbPath, err := sqliteFilePath(cfg.DBDSN)
	if err != nil {
		return err
	}
	if fileExists(dbPath) && !*force {
		return fmt.Errorf("%s already exists; stop the service and re-run with --force to overwrite it", dbPath)
	}

	stage, err := os.MkdirTemp("", "zanskar-restore-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(stage) }()
	if err := extractTarGz(*in, stage); err != nil {
		return err
	}

	manBytes, err := os.ReadFile(filepath.Join(stage, "manifest.json")) // #nosec G304 -- inside our temp dir
	if err != nil {
		return fmt.Errorf("restore: read manifest: %w", err)
	}
	var man backupManifest
	if err := json.Unmarshal(manBytes, &man); err != nil {
		return fmt.Errorf("restore: parse manifest: %w", err)
	}
	if man.KeyFingerprint != "" && man.KeyFingerprint != keyFingerprint(cfg.MasterKey) {
		fmt.Fprintln(os.Stderr, "warning: this backup was sealed with a DIFFERENT master key than the current")
		fmt.Fprintln(os.Stderr, "         ZANSKAR_MASTER_KEY. Stored credentials will not be decryptable. Restore")
		fmt.Fprintln(os.Stderr, "         the original key first if you have it.")
	}

	snap := filepath.Join(stage, "db", "zanskar.db")
	if !fileExists(snap) {
		return errors.New("restore: archive has no database snapshot")
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o750); err != nil {
		return err
	}
	// Remove WAL/SHM siblings so the restored file is authoritative.
	for _, sfx := range []string{"", "-wal", "-shm"} {
		_ = os.Remove(dbPath + sfx)
	}
	if err := copyFile(snap, dbPath, 0o600); err != nil {
		return fmt.Errorf("restore: place database: %w", err)
	}

	if man.RecordingsIncluded {
		if err := copyTree(filepath.Join(stage, "recordings"), cfg.RecordingsDir); err != nil {
			return fmt.Errorf("restore: recordings: %w", err)
		}
	}
	fmt.Printf("Restored the database to %s", dbPath)
	if man.RecordingsIncluded {
		fmt.Printf(" and recordings to %s", cfg.RecordingsDir)
	}
	fmt.Println(".")
	if man.RecordingsBackend == "s3" {
		fmt.Println("Recordings live in S3 and were not part of this archive.")
	}
	fmt.Println("Start the service when ready.")
	return nil
}

// ---- helpers

// maxRestoreEntryBytes caps a single archive entry during restore (16 GiB),
// well above any real recording or SQLite snapshot but a guard against a
// crafted archive claiming an enormous size.
const maxRestoreEntryBytes = 1 << 34

func keyFingerprint(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:])[:16]
}

// sqliteFilePath extracts the on-disk path from a SQLite DSN like
// "file:/var/lib/zanskar/zanskar.db?...". An in-memory database cannot be backed up.
func sqliteFilePath(dsn string) (string, error) {
	s := strings.TrimPrefix(dsn, "file:")
	if i := strings.IndexByte(s, '?'); i >= 0 {
		s = s[:i]
	}
	if s == "" || strings.HasPrefix(s, ":memory:") || strings.Contains(dsn, "mode=memory") {
		return "", errors.New("cannot back up an in-memory database")
	}
	return s, nil
}

func dirExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src) // #nosec G304 -- src is inside our staging dir
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode) // #nosec G304 -- dst is a config-derived or staging path, not attacker input
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil { // #nosec G110 -- our own snapshot, not attacker input
		_ = out.Close()
		return err
	}
	return out.Close()
}

// copyTree copies a directory tree, preserving relative layout with 0700 dirs
// and 0600 files (recordings are sensitive).
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		return copyFile(path, target, 0o600)
	})
}

func writeTarGz(srcDir, outPath string) error {
	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) // #nosec G304 -- operator-chosen archive path
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	walkErr := filepath.WalkDir(srcDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil || rel == "." {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		in, err := os.Open(path) // #nosec G304 G122 -- our freshly-created staging dir, no attacker symlinks
		if err != nil {
			return err
		}
		defer func() { _ = in.Close() }()
		_, err = io.Copy(tw, in) // #nosec G110 -- our own files, not attacker input
		return err
	})
	if walkErr != nil {
		_ = tw.Close()
		_ = gz.Close()
		return walkErr
	}
	if err := tw.Close(); err != nil {
		_ = gz.Close()
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	return f.Close()
}

// extractTarGz unpacks into destDir, refusing any entry that would escape it
// (path traversal) and any non-regular, non-directory entry.
func extractTarGz(archive, destDir string) error {
	f, err := os.Open(archive) // #nosec G304 -- operator-specified backup archive
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	root, err := filepath.Abs(destDir)
	if err != nil {
		return err
	}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		// Reject, not neutralise, any entry that would escape the destination.
		name := filepath.Clean(hdr.Name)
		if name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) || filepath.IsAbs(name) {
			return fmt.Errorf("restore: archive entry escapes destination: %q", hdr.Name)
		}
		target := filepath.Join(root, name)
		if target != root && !strings.HasPrefix(target, root+string(filepath.Separator)) {
			return fmt.Errorf("restore: archive entry escapes destination: %q", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
		case tar.TypeReg:
			// The header size bounds the copy so a crafted archive cannot
			// exhaust the disk; the cap rejects an absurd declared size.
			if hdr.Size < 0 || hdr.Size > maxRestoreEntryBytes {
				return fmt.Errorf("restore: archive entry %q has an invalid size (%d bytes)", hdr.Name, hdr.Size)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) // #nosec G304 -- target validated within destDir above
			if err != nil {
				return err
			}
			// Copy exactly the declared bytes: a short read means a truncated
			// archive and must fail rather than write a partial file.
			if _, err := io.CopyN(out, tr, hdr.Size); err != nil {
				_ = out.Close()
				return fmt.Errorf("restore: entry %q: %w", hdr.Name, err)
			}
			if err := out.Close(); err != nil {
				return err
			}
		default:
			// Skip symlinks and other special entries; a backup has none.
			continue
		}
	}
}

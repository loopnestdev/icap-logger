package main

import (
	"compress/gzip"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// rotatingWriter is an io.WriteCloser that rotates the active log file when it
// exceeds maxSize bytes. On rotation it:
//  1. Renames the active file with a timestamp suffix
//     (e.g. icap_logger.log.20260311-165838)
//  2. Compresses the renamed file to <name>.gz asynchronously
//  3. Deletes the oldest rotated .gz files when the count exceeds fileRetention
//
// All I/O that could block (compression, deletion) runs in a background
// goroutine so the Write() hot-path is never delayed.
type rotatingWriter struct {
	mu             sync.Mutex
	filename        string
	maxSize         int64
	fileRetention   int
	file            *os.File
	size            int64
}

// newRotatingWriter creates a rotatingWriter. maxSizeMB is the per-file
// rotation threshold; fileRetention caps the number of retained .gz archives
// (0 means unlimited).
func newRotatingWriter(filename string, maxSizeMB int64, fileRetention int) (*rotatingWriter, error) {
	w := &rotatingWriter{
		filename:      filename,
		maxSize:       maxSizeMB * 1024 * 1024,
		fileRetention: fileRetention,
	}
	if err := w.openFile(); err != nil {
		return nil, err
	}
	return w, nil
}

// openFile opens (or creates) the active log file in append mode and records
// its current size so the rotation threshold is accurate even across restarts.
func (w *rotatingWriter) openFile() error {
	f, err := os.OpenFile(w.filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	w.file = f
	w.size = fi.Size()
	return nil
}

// rotate closes the active file, renames it, then hands the renamed path to
// a background goroutine for compression and retention enforcement.
func (w *rotatingWriter) rotate() error {
	if w.file != nil {
		w.file.Close()
		w.file = nil
	}

	// Build the rotated filename: base + timestamp suffix (no extension yet).
	rotated := w.filename + "." + time.Now().Format("20060102-150405")
	if err := os.Rename(w.filename, rotated); err != nil {
		// If rename fails (e.g. cross-device), still open a new file so logging
		// continues; the old data is not lost — just not archived.
		slog.Warn("log rotate: rename failed", "err", err)
		return w.openFile()
	}

	// Open the fresh active log file immediately so the Write() caller is never
	// blocked waiting for compression to finish.
	if err := w.openFile(); err != nil {
		return err
	}

	// Compress and enforce retention asynchronously.
	filename := w.filename
	maxOld := w.fileRetention
	go compressAndPrune(rotated, filename, maxOld)

	return nil
}

// Write implements io.Writer. It rotates the file when the size threshold is
// reached, then writes p to the active file.
func (w *rotatingWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.size+int64(len(p)) > w.maxSize && w.size > 0 {
		if err := w.rotate(); err != nil {
			return 0, err
		}
	}
	n, err = w.file.Write(p)
	w.size += int64(n)
	return n, err
}

// Close flushes and closes the active log file.
func (w *rotatingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		return w.file.Close()
	}
	return nil
}

// ── background helpers ────────────────────────────────────────────────────────

// compressAndPrune compresses src to src+".gz", deletes src, then enforces
// the fileRetention limit by removing the oldest .gz archives.
//
// Parameters:
//   - src           — the just-rotated raw log file (e.g. /var/log/icap/icap_logger.log.20260311-165838)
//   - baseName      — the active log file path, used to derive the archive glob
//   - fileRetention — max number of .gz files to keep (0 = unlimited)
func compressAndPrune(src, baseName string, fileRetention int) {
	gz := src + ".gz"

	if err := compressFile(src, gz); err != nil {
		slog.Error("log rotate: compression failed", "src", src, "err", err)
		// Keep the uncompressed file — do not delete it.
		return
	}

	// Remove the uncompressed original only after successful compression.
	if err := os.Remove(src); err != nil {
		slog.Warn("log rotate: could not remove uncompressed file after compression",
			"file", src, "err", err)
	}

	slog.Info("log rotate: compressed", "archive", gz)

	if fileRetention <= 0 {
		return
	}
	pruneOldArchives(baseName, fileRetention)
}

// compressFile reads src, writes a gzip-compressed copy to dst, and syncs
// dst to disk before returning. The source file is NOT removed here.
func compressFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}

	gz := gzip.NewWriter(out)
	gz.Name = filepath.Base(src)
	gz.ModTime = time.Now()

	if _, err := io.Copy(gz, in); err != nil {
		gz.Close()
		out.Close()
		os.Remove(dst) // clean up partial archive
		return err
	}
	if err := gz.Close(); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// pruneOldArchives lists all .gz archives whose names start with the base log
// filename, sorts them oldest-first by name (the timestamp suffix makes
// lexicographic order == chronological order), and removes files beyond
// the fileRetention limit.
func pruneOldArchives(baseName string, fileRetention int) {
	// 0 means unlimited — never prune.
	if fileRetention <= 0 {
		return
	}
	dir := filepath.Dir(baseName)
	base := filepath.Base(baseName)

	entries, err := os.ReadDir(dir)
	if err != nil {
		slog.Warn("log rotate: could not read log directory for pruning",
			"dir", dir, "err", err)
		return
	}

	// Collect all compressed archive files that belong to this log.
	// Pattern: <base>.<timestamp>.gz  e.g. icap_logger.log.20260311-165838.gz
	var archives []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() {
			continue
		}
		if strings.HasPrefix(name, base+".") && strings.HasSuffix(name, ".gz") {
			archives = append(archives, filepath.Join(dir, name))
		}
	}

	if len(archives) <= fileRetention {
		return // within limit — nothing to prune
	}

	// Sort ascending by name — the timestamp suffix (YYYYMMDD-HHMMSS) makes
	// this equivalent to chronological order. Oldest files are removed first.
	sort.Strings(archives)

	toDelete := archives[:len(archives)-fileRetention]
	for _, path := range toDelete {
		if err := os.Remove(path); err != nil {
			slog.Warn("log rotate: could not prune old archive",
				"file", path, "err", err)
		} else {
			slog.Info("log rotate: pruned old archive", "file", path)
		}
	}
}

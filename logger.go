package main

import (
	"os"
	"sync"
	"time"
)

// rotatingWriter is an io.WriteCloser that rotates the log file when it
// exceeds maxSize bytes. The rotated file is renamed with a timestamp suffix.
type rotatingWriter struct {
	mu       sync.Mutex
	filename string
	maxSize  int64
	file     *os.File
	size     int64
}

func newRotatingWriter(filename string, maxSizeMB int64) (*rotatingWriter, error) {
	w := &rotatingWriter{
		filename: filename,
		maxSize:  maxSizeMB * 1024 * 1024,
	}
	if err := w.openFile(); err != nil {
		return nil, err
	}
	return w, nil
}

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

func (w *rotatingWriter) rotate() error {
	if w.file != nil {
		w.file.Close()
		w.file = nil
	}
	newName := w.filename + "." + time.Now().Format("20060102-150405")
	_ = os.Rename(w.filename, newName)
	return w.openFile()
}

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

func (w *rotatingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		return w.file.Close()
	}
	return nil
}

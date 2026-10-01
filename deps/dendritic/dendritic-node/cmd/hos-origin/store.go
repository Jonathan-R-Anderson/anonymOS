package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

// Store is the origin's state directory: small JSON snapshots written atomically (write a
// temporary file, fsync, rename), and append-only JSON-lines logs.  A single VPS, a few
// thousand nodes and a crash report now and then do not need a database.
type Store struct{ dir string }

func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

func (s *Store) Path(name string) string { return filepath.Join(s.dir, name) }

func (s *Store) SaveJSON(name string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return s.WriteFileAtomic(name, b)
}

func (s *Store) WriteFileAtomic(name string, b []byte) error {
	dst := s.Path(name)
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dst)
}

func (s *Store) LoadJSON(name string, v any) error {
	b, err := os.ReadFile(s.Path(name))
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// AppendLine appends one JSON value as a line to a log file.
func (s *Store) AppendLine(name string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(s.Path(name), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(b, '\n'))
	return err
}

// readBody reads at most limit bytes of a request body; more is an error, not a truncation.
func readBody(r *http.Request, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("request body too large")
	}
	return b, nil
}

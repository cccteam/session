package deviceflow

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/go-playground/errors/v5"
)

// The pairs of a directory live in one file, a map from server|outlet to the pair,
// beside the lock file every refresh and write holds.
const (
	tokensFileName = "tokens.json"
	lockFileName   = "tokens.lock"
	// dirMode and fileMode keep the directory and the files to the person.
	dirMode  = 0o700
	fileMode = 0o600
)

// record is one pair as the file keeps it.
type record struct {
	AccessToken     string    `json:"accessToken"`
	RefreshToken    string    `json:"refreshToken"`
	AccessExpiresAt time.Time `json:"accessExpiresAt"`
	ObtainedAt      time.Time `json:"obtainedAt"`
}

// store is the pair of one server and outlet in one directory.
type store struct {
	dir string
	key string
}

// read is the stored pair, and whether there is one.
func (s *store) read() (*record, bool, error) {
	all, err := s.readAll()
	if err != nil {
		return nil, false, err
	}
	rec, ok := all[s.key]
	if !ok {
		return nil, false, nil
	}

	return &rec, true, nil
}

// save stores rec under the lock, as Login does.
func (s *store) save(rec *record) error {
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()

	return s.write(rec)
}

// write stores rec; the caller holds the lock.
func (s *store) write(rec *record) error {
	all, err := s.readAll()
	if err != nil {
		return err
	}
	all[s.key] = *rec

	return s.writeAll(all)
}

// forget removes the stored pair under the lock, as Logout does.
func (s *store) forget() error {
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()

	return s.remove()
}

// remove removes the stored pair; the caller holds the lock.
func (s *store) remove() error {
	all, err := s.readAll()
	if err != nil {
		return err
	}
	if _, ok := all[s.key]; !ok {
		return nil
	}
	delete(all, s.key)

	return s.writeAll(all)
}

// lock takes the directory's lock and returns what releases it. The directory is
// created when it is missing.
func (s *store) lock() (unlock func(), err error) {
	if err := os.MkdirAll(s.dir, dirMode); err != nil {
		return nil, errors.Wrap(err, "os.MkdirAll()")
	}
	f, err := os.OpenFile(filepath.Join(s.dir, lockFileName), os.O_CREATE|os.O_RDWR, fileMode)
	if err != nil {
		return nil, errors.Wrap(err, "os.OpenFile()")
	}
	if err := lockFile(f); err != nil {
		_ = f.Close()

		return nil, err
	}

	return func() {
		_ = unlockFile(f)
		_ = f.Close()
	}, nil
}

// readAll reads the file; a missing file holds nothing.
func (s *store) readAll() (map[string]record, error) {
	path := filepath.Join(s.dir, tokensFileName)
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]record{}, nil
	}
	if err != nil {
		return nil, errors.Wrap(err, "os.ReadFile()")
	}
	all := map[string]record{}
	if err := json.Unmarshal(raw, &all); err != nil {
		return nil, errors.Wrapf(err, "%s does not hold the stored sign-ins", path)
	}

	return all, nil
}

// writeAll writes the file whole, through a temporary file renamed over it, so a
// reader sees the old file or the new one and never a part.
func (s *store) writeAll(all map[string]record) error {
	if err := os.MkdirAll(s.dir, dirMode); err != nil {
		return errors.Wrap(err, "os.MkdirAll()")
	}
	tmp, err := os.CreateTemp(s.dir, "tokens-*.json")
	if err != nil {
		return errors.Wrap(err, "os.CreateTemp()")
	}
	if err := writeJSON(tmp, all); err != nil {
		_ = os.Remove(tmp.Name())

		return err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(s.dir, tokensFileName)); err != nil {
		_ = os.Remove(tmp.Name())

		return errors.Wrap(err, "os.Rename()")
	}

	return nil
}

// writeJSON writes all to f, with the person's mode, and closes it.
func writeJSON(f *os.File, all map[string]record) error {
	defer f.Close()

	if err := f.Chmod(fileMode); err != nil {
		return errors.Wrap(err, "os.File.Chmod()")
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(all); err != nil {
		return errors.Wrap(err, "json.Encoder.Encode()")
	}
	if err := f.Sync(); err != nil {
		return errors.Wrap(err, "os.File.Sync()")
	}
	if err := f.Close(); err != nil {
		return errors.Wrap(err, "os.File.Close()")
	}

	return nil
}

// Package settings persists small app-wide preferences, such as whether
// discovery may try the system SSH agent against a station.
package settings

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

type Values struct {
	AllowSSHAgent bool `json:"allowSSHAgent"`
}

type Store struct {
	mu   sync.Mutex
	path string
	v    Values
}

func New(dir string) *Store {
	s := &Store{path: filepath.Join(dir, "settings.json")}
	s.load()
	return s
}

func (s *Store) load() {
	b, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	_ = json.Unmarshal(b, &s.v)
}

func (s *Store) Get() Values {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.v
}

func (s *Store) SetAllowSSHAgent(allow bool) error {
	s.mu.Lock()
	s.v.AllowSSHAgent = allow
	v := s.v
	s.mu.Unlock()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0o644)
}

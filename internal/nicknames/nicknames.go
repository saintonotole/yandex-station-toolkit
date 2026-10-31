// Package nicknames persists per-device nicknames and case colors keyed by
// deviceId, falling back to MAC, so settings survive IP changes.
package nicknames

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type Meta struct {
	Nickname string `json:"nickname,omitempty"`
	Color    string `json:"color,omitempty"`
}

type Store struct {
	mu      sync.Mutex
	path    string
	byDevID map[string]Meta
	byMAC   map[string]Meta
}

func New(dir string) *Store {
	path := filepath.Join(dir, "nicknames.json")
	s := &Store{
		path:    path,
		byDevID: map[string]Meta{},
		byMAC:   map[string]Meta{},
	}
	s.load()
	return s
}

func (s *Store) load() {
	b, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	// Older files store a plain nickname string instead of an object.
	var raw struct {
		ByDevID map[string]json.RawMessage `json:"byDeviceId"`
		ByMAC   map[string]json.RawMessage `json:"byMac"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return
	}
	parse := func(m map[string]json.RawMessage) map[string]Meta {
		out := map[string]Meta{}
		for k, v := range m {
			var meta Meta
			if len(v) > 0 && v[0] == '"' {
				_ = json.Unmarshal(v, &meta.Nickname)
			} else {
				_ = json.Unmarshal(v, &meta)
			}
			out[k] = meta
		}
		return out
	}
	s.byDevID = parse(raw.ByDevID)
	s.byMAC = parse(raw.ByMAC)
}

func (s *Store) save() error {
	raw := struct {
		ByDevID map[string]Meta `json:"byDeviceId"`
		ByMAC   map[string]Meta `json:"byMac"`
	}{s.byDevID, s.byMAC}
	b, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0o644)
}

func (s *Store) Lookup(deviceID, mac string) string {
	return s.meta(deviceID, mac).Nickname
}

func (s *Store) LookupColor(deviceID, mac string) string {
	return s.meta(deviceID, mac).Color
}

func (s *Store) meta(deviceID, mac string) Meta {
	s.mu.Lock()
	defer s.mu.Unlock()
	if deviceID != "" {
		if m, ok := s.byDevID[deviceID]; ok {
			return m
		}
	}
	if mac != "" {
		if m, ok := s.byMAC[mac]; ok {
			return m
		}
	}
	return Meta{}
}

func (s *Store) Set(deviceID, mac, nickname string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	nick := truncate(strings.TrimSpace(nickname), 64)
	s.update(deviceID, mac, func(m Meta) Meta {
		m.Nickname = nick
		return m
	})
	return s.save()
}

func (s *Store) SetColor(deviceID, mac, color string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.update(deviceID, mac, func(m Meta) Meta {
		m.Color = strings.TrimSpace(color)
		return m
	})
	return s.save()
}

func (s *Store) update(deviceID, mac string, fn func(Meta) Meta) {
	apply := func(store map[string]Meta, key string) {
		if key == "" {
			return
		}
		m := fn(store[key])
		if m.Nickname == "" && m.Color == "" {
			delete(store, key)
			return
		}
		store[key] = m
	}
	apply(s.byDevID, deviceID)
	apply(s.byMAC, mac)
}

func truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"strings"
)

//go:embed payloads
var payloadsFS embed.FS

const (
	payloadDropbear = "dropbearmulti" // scripts/build-dropbear.sh
	payloadNoUpdate = "yandex-noupdate.sh"
	// The station-trusted chain for the bootstrap endpoint (lite-kit, MIT)
	// and the local fallback sync answer.
	payloadEquasarChain = "equasar-fullchain.pem"
	payloadEquasarKey   = "equasar-key.pem"
	payloadSyncTemplate = "equasar-sync-template.json"
)

// payload validates the bytes so a broken checkout fails here instead of
// pushing garbage to a device.
func payload(name string) ([]byte, error) {
	b, err := payloadsFS.ReadFile("payloads/" + name)
	if err != nil {
		return nil, fmt.Errorf("payload %s is not embedded: restore it under payloads/ before building", name)
	}
	switch name {
	case payloadDropbear:
		if len(b) < 100_000 || b[0] != 0x7f || b[1] != 'E' {
			return nil, fmt.Errorf("payload %s looks invalid (%d bytes): restore it under payloads/", name, len(b))
		}
	case payloadNoUpdate:
		if len(b) < 500 || string(b[:2]) != "#!" {
			return nil, fmt.Errorf("payload %s looks invalid: restore it under payloads/", name)
		}
	case payloadEquasarChain, payloadEquasarKey:
		if len(b) < 200 || !strings.HasPrefix(string(b), "-----BEGIN") {
			return nil, fmt.Errorf("payload %s looks invalid (%d bytes): restore it under payloads/", name, len(b))
		}
	case payloadSyncTemplate:
		if len(b) < 100 || !json.Valid(b) {
			return nil, fmt.Errorf("payload %s looks invalid (%d bytes): restore it under payloads/", name, len(b))
		}
	}
	return b, nil
}

func payloadStatus() map[string]any {
	st := map[string]any{}
	for _, name := range []string{payloadDropbear, payloadNoUpdate, payloadEquasarChain, payloadEquasarKey, payloadSyncTemplate} {
		_, err := payload(name)
		st[name] = err == nil
	}
	return st
}

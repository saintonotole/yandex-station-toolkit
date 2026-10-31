package server

import (
	"encoding/json"
	"fmt"
)

// adbdCommand is what every sync answer carries, in every branch different
// firmware generations read.
func adbdCommand() map[string]any {
	return map[string]any{
		"remoteActivation": true,
		"network":          true,
		"fullDurationMs":   31536000000,
	}
}

// builtinSyncTemplate is the minimal answer used when no template payload is
// embedded at all.
const builtinSyncTemplate = `{"status":"ok","config":{"account_config":{"spotter":"alisa"},"device_config":{"name":"quasar"},"system_config":{"adbd":{"remoteActivation":true,"network":true,"fullDurationMs":31536000000}},"adbd":{"remoteActivation":true,"network":true,"fullDurationMs":31536000000}},"subscription":{"mode":"transaction"}}`

// loadSyncTemplate parses the template payload and strips everything private
// before it can ever be sent to a device (lite-kit's _sanitize).
func loadSyncTemplate(b []byte) (map[string]any, error) {
	if len(b) == 0 {
		b = []byte(builtinSyncTemplate)
	}
	var d map[string]any
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("Server: sync template: %w", err)
	}
	if len(d) == 0 {
		return nil, fmt.Errorf("Server: sync template is empty")
	}
	sanitizeSync(d)
	return d, nil
}

// sanitizeSync removes secrets and device-specific fields from a template:
// the station's local certificate and key, the user's Wi-Fi hash, and the
// user's coordinates. The fields are dropped, not blanked, so the device
// keeps its own values.
func sanitizeSync(d map[string]any) {
	delete(d, "glagol")
	if cfg, ok := d["config"].(map[string]any); ok {
		if acc, ok := cfg["account_config"].(map[string]any); ok {
			delete(acc, "user_wifi_config")
		}
		if dev, ok := cfg["device_config"].(map[string]any); ok {
			delete(dev, "location")
		}
	}
}

// injectADBD writes the ADB activation into every branch a firmware
// generation may read, and makes sure the answer reports success.
func injectADBD(d map[string]any) {
	cfg, _ := d["config"].(map[string]any)
	if cfg == nil {
		cfg = map[string]any{}
		d["config"] = cfg
	}
	for _, section := range []string{"system_config", "device_config"} {
		sub, _ := cfg[section].(map[string]any)
		if sub == nil {
			sub = map[string]any{}
			cfg[section] = sub
		}
		sub["adbd"] = adbdCommand()
	}
	cfg["adbd"] = adbdCommand()
	d["adbd"] = adbdCommand()
	if _, ok := d["status"]; !ok {
		d["status"] = "ok"
	}
}

func marshalSync(d map[string]any) []byte {
	out, err := json.Marshal(d)
	if err != nil {
		// The map came from JSON, so it marshals; keep a hard guarantee anyway.
		return []byte(builtinSyncTemplate)
	}
	return out
}

// syncFromUpstream injects ADB activation into a real Yandex answer. The
// answer is returned unchanged in shape — only the adbd fields differ — so
// the station keeps every native field for its model.
func syncFromUpstream(raw []byte) ([]byte, bool) {
	var d map[string]any
	if err := json.Unmarshal(raw, &d); err != nil || len(d) == 0 {
		return nil, false
	}
	injectADBD(d)
	return marshalSync(d), true
}

package sshkeys

import (
	"strings"
	"testing"
)

func ed25519Line(t *testing.T) string {
	t.Helper()
	_, pub, err := GenerateEd25519("test@station-tool")
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func TestParseAuthorizedKeys(t *testing.T) {
	line := ed25519Line(t)

	keys, err := ParseAuthorizedKeys("# comment\n\n" + line + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].Type != "ssh-ed25519" || keys[0].Comment != "test@station-tool" {
		t.Fatalf("parsed: %+v", keys)
	}
	if keys[0].Line() != line {
		t.Fatalf("roundtrip: %q != %q", keys[0].Line(), line)
	}

	if _, err := ParseAuthorizedKeys(""); err == nil {
		t.Fatal("empty must fail")
	}
	// The declared type does not match the key blob.
	bad := strings.Replace(line, "ssh-ed25519", "ssh-rsa", 1)
	if _, err := ParseAuthorizedKeys(bad); err == nil {
		t.Fatal("type/blob mismatch must fail")
	}
	if _, err := ParseAuthorizedKeys("ssh-ed25519 not-base64!!! x"); err == nil {
		t.Fatal("bad base64 must fail")
	}
	if _, err := ParseAuthorizedKeys("garbage"); err == nil {
		t.Fatal("garbage must fail")
	}
	if _, err := ParseAuthorizedKeys("unknown-type AAAA x"); err == nil {
		t.Fatal("unknown type must fail")
	}
}

func TestMergeKeys(t *testing.T) {
	a := []PubKey{{Type: "ssh-ed25519", Blob: "AAA"}}
	b := []PubKey{{Type: "ssh-ed25519", Blob: "AAA", Comment: "dup"}, {Type: "ssh-rsa", Blob: "BBB"}}
	m := MergeKeys(a, b)
	if len(m) != 2 {
		t.Fatalf("merge: %+v", m)
	}
	if m[1].Blob != "BBB" {
		t.Fatalf("order: %+v", m)
	}
}

func TestGenerateEd25519RoundTrip(t *testing.T) {
	priv, pub, err := GenerateEd25519("station-tool-test")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(priv, "-----BEGIN OPENSSH PRIVATE KEY-----") {
		t.Fatalf("priv format: %.40s", priv)
	}
	k, err := ParseKeyLine(pub)
	if err != nil {
		t.Fatalf("pub not parseable: %v (%s)", err, pub)
	}
	if k.Type != "ssh-ed25519" {
		t.Fatalf("type: %s", k.Type)
	}
	if !strings.Contains(pub, "station-tool-test") {
		t.Fatalf("comment lost: %s", pub)
	}
}

func TestParseDeviceAuthorizedKeysSkipsBad(t *testing.T) {
	good := ed25519Line(t)
	keys := ParseDeviceAuthorizedKeys("junk line\n" + good + "\n# c\n")
	if len(keys) != 1 || keys[0].Comment != "test@station-tool" {
		t.Fatalf("keys: %+v", keys)
	}
}

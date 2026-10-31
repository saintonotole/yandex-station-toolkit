package provision

import (
	"encoding/hex"
	"strings"
	"testing"
)

// The reference frames come from the wiki's verified helper
// (contrib/alice-say.py --dry-run and its frame builder, run for the
// same inputs). Byte equality here proves the Go port speaks exactly
// what the verified Plum run spoke.
func TestVocalizeFramesMatchReference(t *testing.T) {
	sub := hexEncode(subscribeFrame())
	wantSub := "2c000000e20f253a0f416c6963654361706162696c697479a201110a0f416c6963654361706162696c697479e80fd201"
	if sub != wantSub {
		t.Fatalf("subscribe frame mismatch:\n got %s\nwant %s", sub, wantSub)
	}
	voc := hexEncode(vocalizeFrame("Test"))
	wantVoc := "28000000e20f213a0f416c6963654361706162696c697479420e081218016a080a04546573741001e80fd201"
	if voc != wantVoc {
		t.Fatalf("vocalize frame mismatch:\n got %s\nwant %s", voc, wantVoc)
	}
	if !strings.HasPrefix(voc, "28000000") {
		t.Fatal("the length prefix must be uint32 little-endian")
	}
}

func hexEncode(b []byte) string { return hex.EncodeToString(b) }

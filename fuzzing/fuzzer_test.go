package fuzzing

import (
	"testing"
)

func TestParseStatusCodes(t *testing.T) {
	codes := ParseStatusCodes("200,301,404")
	if len(codes) != 3 {
		t.Fatalf("Expected 3 status codes, got %d", len(codes))
	}
	if codes[0] != 200 || codes[1] != 301 || codes[2] != 404 {
		t.Fatalf("Unexpected status codes: %v", codes)
	}
}

func TestParseExtensions(t *testing.T) {
	exts := ParseExtensions(".php,.html,.json")
	if len(exts) != 3 {
		t.Fatalf("Expected 3 extensions, got %d", len(exts))
	}
}

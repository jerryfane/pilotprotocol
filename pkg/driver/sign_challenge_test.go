package driver

import (
	"strings"
	"testing"
)

func TestSignChallengeRejectsOversizedPayloadBeforeIPC(t *testing.T) {
	d := &Driver{}
	_, err := d.SignChallenge(make([]byte, maxSignChallengePayload+1))
	if err == nil {
		t.Fatal("SignChallenge oversized payload err = nil")
	}
	if !strings.Contains(err.Error(), "payload exceeds 4096 bytes") {
		t.Fatalf("SignChallenge oversized payload err = %v, want payload limit", err)
	}
}

package gossip

import "testing"

func TestHasCap(t *testing.T) {
	if HasCap(0, CapGossip) {
		t.Fatalf("expected CapGossip unset in 0")
	}
	if !HasCap(CapGossip, CapGossip) {
		t.Fatalf("expected CapGossip set in CapGossip bitmap")
	}
	if !HasCap(CapGossip|0b1000, CapGossip) {
		t.Fatalf("CapGossip should coexist with other bits")
	}
	if HasCap(0b1000, CapGossip) {
		t.Fatalf("unrelated bit must not read as CapGossip")
	}
}

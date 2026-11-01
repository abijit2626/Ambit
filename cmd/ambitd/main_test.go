package main

import (
	"fmt"
	"testing"

	"github.com/abijit2626/ambit/internal/egress"
	"github.com/abijit2626/ambit/internal/event"
)

func TestEgressHealthSaysOnFullOrOff(t *testing.T) {
	if got := egressHealth(nil); got.State != event.EgressProfileOff || got.Destinations != 0 {
		t.Errorf("no profile: %+v", got)
	}
	p := egress.NewMemory(2)
	if err := p.Record("hmac:a"); err != nil {
		t.Fatal(err)
	}
	if got := egressHealth(p); got.State != event.EgressProfileOn || got.Destinations != 1 {
		t.Errorf("learning: %+v", got)
	}
	big := egress.NewMemory(0)
	for i := 0; i < egress.DefaultMaxDestinations; i++ {
		if err := big.Record(fmt.Sprintf("hmac:%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if got := egressHealth(big); got.State != event.EgressProfileFull || got.Destinations != egress.DefaultMaxDestinations {
		t.Errorf("full: %+v", got)
	}
}

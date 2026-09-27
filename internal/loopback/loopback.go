// Package loopback validates that a listener binds only a loopback address.
//
// This is a security control with two call sites — the hook endpoint and the
// OTLP receiver — so it lives in one place. Two copies of a control like this is
// exactly the thing that drifts: someone relaxes one and nobody notices the
// other still disagrees.
//
// Binding either endpoint off-loopback would expose an agent-fleet decision
// surface and a telemetry ingest to anything on the network, and would put
// remote latency in the tool-call path. See docs/02-architecture.md.
package loopback

import (
	"errors"
	"net"
)

// Validate reports whether addr is a loopback bind address.
//
// Kept separate from any Listen call so the policy is testable without
// depending on the host having a working stack for the address family — a
// container with IPv6 disabled would otherwise fail such a test for the wrong
// reason.
func Validate(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("listener must bind a loopback address; " + addr + " is not loopback")
	}
	return nil
}

// Listen opens a TCP listener, refusing any non-loopback bind.
func Listen(addr string) (net.Listener, error) {
	if err := Validate(addr); err != nil {
		return nil, err
	}
	return net.Listen("tcp", addr)
}

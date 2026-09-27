package loopback

import "testing"

func TestValidate(t *testing.T) {
	refuse := []string{
		"0.0.0.0:4318", "192.168.1.10:7777", "[::]:4318",
		"10.0.0.5:7777", "example.com:4318", "not-an-addr",
	}
	for _, addr := range refuse {
		if err := Validate(addr); err == nil {
			t.Errorf("Validate(%q) = nil; must refuse non-loopback binds", addr)
		}
	}
	accept := []string{"127.0.0.1:0", "127.0.0.1:4318", "localhost:0", "[::1]:0", "127.0.0.53:7777"}
	for _, addr := range accept {
		if err := Validate(addr); err != nil {
			t.Errorf("Validate(%q) = %v, want nil", addr, err)
		}
	}
}

func TestListenRefusesWildcard(t *testing.T) {
	if ln, err := Listen("0.0.0.0:0"); err == nil {
		ln.Close()
		t.Error("Listen(0.0.0.0:0) succeeded; must refuse a wildcard bind")
	}
	ln, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(127.0.0.1:0) failed: %v", err)
	}
	ln.Close()
}

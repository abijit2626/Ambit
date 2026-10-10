package loopback

import (
	"errors"
	"net"
)

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

func Listen(addr string) (net.Listener, error) {
	if err := Validate(addr); err != nil {
		return nil, err
	}
	return net.Listen("tcp", addr)
}

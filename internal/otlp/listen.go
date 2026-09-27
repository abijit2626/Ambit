package otlp

import (
	"net"

	"github.com/abijit2626/ambit/internal/loopback"
)

func loopbackListen(addr string) (net.Listener, error) { return loopback.Listen(addr) }

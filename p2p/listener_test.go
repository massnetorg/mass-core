// +build !network

package p2p

import (
	"bytes"
	"testing"

	"github.com/massnetorg/mass-core/config"
	"github.com/massnetorg/mass-core/testutil"
)

func TestListener(t *testing.T) {
	testutil.SkipCI(t)
	// Create a listener
	cfg := &config.Config{
		P2P: &config.P2P{
			SkipUpnp:      true,
			ListenAddress: "tcp://0.0.0.0:43480",
		},
	}
	l, _ := NewDefaultListener(cfg)

	// Dial the listener
	lAddr := l.ExternalAddress()
	connOut, err := lAddr.Dial()
	if err != nil {
		t.Fatalf("Could not connect to listener address %v", lAddr)
	} else {
		t.Logf("Created a connection to listener address %v", lAddr)
	}
	connIn, ok := <-l.Connections()
	if !ok {
		t.Fatalf("Could not get inbound connection from listener")
	}

	msg := []byte("hi!")
	go connIn.Write(msg)
	b := make([]byte, 32)
	n, err := connOut.Read(b)
	if err != nil {
		t.Fatalf("Error reading off connection: %v", err)
	}

	b = b[:n]
	if !bytes.Equal(msg, b) {
		t.Fatalf("Got %s, expected %s", b, msg)
	}

	// Close the server, no longer needed.
	l.Stop()
}

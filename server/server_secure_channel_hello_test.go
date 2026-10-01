// Copyright 2021 Converter Systems LLC. All rights reserved.

package server

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/awcullen/opcua/ua"
)

// openWithHello opens a server secure channel, sends it the Hello message and
// returns the error with which the channel's Open fails.
func openWithHello(t *testing.T, hello []byte) error {
	t.Helper()
	srv := &Server{
		maxBufferSize:  defaultMaxBufferSize,
		maxMessageSize: defaultMaxMessageSize,
		maxChunkCount:  defaultMaxChunkCount,
	}
	conn, peer := net.Pipe()
	defer peer.Close()
	ch := newServerSecureChannel(srv, conn, false)
	done := make(chan error, 1)
	go func() {
		done <- ch.Open()
		conn.Close()
	}()
	peer.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := peer.Write(hello); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for Open")
		return nil
	}
}

// helloMessage returns a Hello message whose EndpointUrl has the given encoded
// length followed by the given bytes.
func helloMessage(urlLength int32, url string) []byte {
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.LittleEndian, ua.MessageTypeHello)
	binary.Write(buf, binary.LittleEndian, uint32(32+len(url)))
	binary.Write(buf, binary.LittleEndian, protocolVersion)
	binary.Write(buf, binary.LittleEndian, defaultMaxBufferSize)
	binary.Write(buf, binary.LittleEndian, defaultMaxBufferSize)
	binary.Write(buf, binary.LittleEndian, defaultMaxMessageSize)
	binary.Write(buf, binary.LittleEndian, defaultMaxChunkCount)
	binary.Write(buf, binary.LittleEndian, urlLength)
	buf.WriteString(url)
	return buf.Bytes()
}

func TestHelloEndpointURLTooLong(t *testing.T) {
	url := "opc.tcp://localhost:4840/" + strings.Repeat("a", 4096)
	err := openWithHello(t, helloMessage(int32(len(url)), url))
	if err != ua.BadTCPEndpointURLInvalid {
		t.Fatalf("expected BadTCPEndpointURLInvalid, got %v", err)
	}
}

func TestHelloEndpointURLExceedsMessage(t *testing.T) {
	// the EndpointUrl claims to be longer than the rest of the message.
	err := openWithHello(t, helloMessage(1000, "opc.tcp://localhost:4840"))
	if err != ua.BadDecodingError {
		t.Fatalf("expected BadDecodingError, got %v", err)
	}
	err = openWithHello(t, helloMessage(0x7FFFFFFF, "opc.tcp://localhost:4840"))
	if err != ua.BadDecodingError {
		t.Fatalf("expected BadDecodingError, got %v", err)
	}
}

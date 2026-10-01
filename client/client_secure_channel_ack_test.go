// Copyright 2021 Converter Systems LLC. All rights reserved.

package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/awcullen/opcua/ua"
)

// openWithReply opens a client secure channel to a listener that answers the
// Hello message with reply, and returns the error with which Open fails.
func openWithReply(t *testing.T, reply []byte) error {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		header := make([]byte, 8)
		if _, err := io.ReadFull(conn, header); err != nil {
			return
		}
		hello := make([]byte, binary.LittleEndian.Uint32(header[4:])-8)
		if _, err := io.ReadFull(conn, hello); err != nil {
			return
		}
		conn.Write(reply)
		// wait for the client to close the connection.
		io.Copy(io.Discard, conn)
	}()
	ch := newClientSecureChannel(
		ua.ApplicationDescription{}, nil, nil,
		"opc.tcp://"+ln.Addr().String(),
		ua.SecurityPolicyURINone, ua.MessageSecurityModeNone, nil,
		5000, "", "", "", "", "", false, false, false, false, 0, 0, 0,
		defaultMaxBufferSize, defaultMaxMessageSize, defaultMaxChunkCount, false)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = ch.Open(ctx)
	if ch.conn != nil {
		ch.conn.Close()
	}
	return err
}

// errorMessage returns an Error message whose reason has the given encoded
// length followed by the given bytes.
func errorMessage(code ua.StatusCode, reasonLength int32, reason string) []byte {
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.LittleEndian, ua.MessageTypeError)
	binary.Write(buf, binary.LittleEndian, uint32(16+len(reason)))
	binary.Write(buf, binary.LittleEndian, uint32(code))
	binary.Write(buf, binary.LittleEndian, reasonLength)
	buf.WriteString(reason)
	return buf.Bytes()
}

func TestOpenReceivesError(t *testing.T) {
	reason := "endpoint not found"
	err := openWithReply(t, errorMessage(ua.BadTCPEndpointURLInvalid, int32(len(reason)), reason))
	if err != ua.BadTCPEndpointURLInvalid {
		t.Fatalf("expected BadTCPEndpointURLInvalid, got %v", err)
	}
}

func TestOpenReceivesErrorReasonExceedsMessage(t *testing.T) {
	// the reason claims to be longer than the rest of the message, which must not
	// be read from the rest of the receive buffer.
	err := openWithReply(t, errorMessage(ua.BadTCPEndpointURLInvalid, 65520, ""))
	if err != ua.BadDecodingError {
		t.Fatalf("expected BadDecodingError, got %v", err)
	}
}

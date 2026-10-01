package securechannel

import (
	"math"

	"github.com/awcullen/opcua/ua"
)

const (
	// maxSequenceNumberBeforeRollover is the sequence number that a sender must reach before it
	// may roll over to a small sequence number (UInt32.MaxValue - 1024).
	maxSequenceNumberBeforeRollover uint32 = math.MaxUint32 - 1024

	// maxSequenceNumberAfterRollover is the exclusive limit of the first sequence number after a rollover.
	maxSequenceNumberAfterRollover uint32 = 1024
)

// SequenceNumberValidator checks the sequence numbers of the message chunks received on a
// secure channel. For the RSA based security policies (OPC UA Part 6, 6.7.2.4), the sequence
// number increases by exactly one for each chunk sent on the channel, regardless of the message
// type (OPN, MSG, CLO) or the security token. It may only roll over once it exceeds
// UInt32.MaxValue - 1024, and the first sequence number after a rollover is less than 1024.
//
// The zero value accepts any sequence number for the first chunk.
type SequenceNumberValidator struct {
	last     uint32
	received bool
}

// Validate returns ua.BadSequenceNumberInvalid if n is not a valid sequence number for the next
// chunk received on the channel, i.e. if the chunk is a duplicate (replay), is out of order, or
// follows a lost chunk. Otherwise it records n as the last received sequence number.
// Validate must only be called after the signature of the chunk has been verified, so that
// unauthenticated chunks cannot change the expected sequence number.
func (v *SequenceNumberValidator) Validate(n uint32) error {
	if v.received && !isNextSequenceNumber(v.last, n) {
		return ua.BadSequenceNumberInvalid
	}
	v.last, v.received = n, true
	return nil
}

// isNextSequenceNumber returns true if next is a valid successor of last.
func isNextSequenceNumber(last, next uint32) bool {
	if next == last+1 {
		return true
	}
	// Rollover. Senders must exceed UInt32.MaxValue - 1024 before rolling over; accepting a
	// rollover from that value itself also tolerates senders that roll over right after it.
	return last >= maxSequenceNumberBeforeRollover && next < maxSequenceNumberAfterRollover
}

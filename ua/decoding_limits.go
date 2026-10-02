// Copyright 2021 Converter Systems LLC. All rights reserved.

package ua

// DecodingLimits limits the memory that a BinaryDecoder allocates for the values it
// decodes from one input.
//
// Decoded values may take much more memory than their encoding: a DataValue encoded
// in one byte takes 88 bytes, so without a limit, a message of the maximum size could
// be decoded into gigabytes. The values decoded from n bytes of input may take
// MinMemory + MemoryPerInputByte * n bytes of memory, but no more than MaxMemory
// bytes. A MemoryPerInputByte or MaxMemory of zero disables that part of the limit.
// Decoding fails with BadEncodingLimitsExceeded if the values would take more.
//
// The memory of Strings, ByteStrings and arrays is counted, as is the memory that
// Variants, NodeIDs, ExtensionObjects and DiagnosticInfos hold, by the size of the
// Go types involved. An array is counted in full as soon as its length has been
// checked against the remaining input, so that one that is too large is rejected
// before memory is allocated for it. If the length of the input is unknown, the
// input decoded so far is used, and Strings, ByteStrings and arrays are decoded in
// chunks that are counted as they are allocated, and then joined, which briefly
// takes twice their memory. The list of the chunks of an array is counted too, so
// such arrays need a MinMemory that leaves room for it.
type DecodingLimits struct {
	// MaxMemory is the most memory, in bytes, that the values decoded from one input
	// may take, or zero for no limit.
	MaxMemory int64
	// MinMemory is the memory, in bytes, that the values decoded from any input may
	// take, in addition to MemoryPerInputByte for each byte of input.
	MinMemory int64
	// MemoryPerInputByte is the memory, in bytes, that the values decoded from one
	// input may take per byte of input, or zero for no limit.
	MemoryPerInputByte int64
}

// DefaultDecodingLimits are the limits of the BinaryDecoders whose EncodingContext
// does not implement DecodingLimitsProvider, which includes the decoders of the client
// and server.
//
// The values of realistic messages take up to about 30 bytes of memory per byte of
// encoding (for example an array of DataValues that each hold a Boolean without
// timestamps or status code), so they are allowed 32 bytes per byte of input, plus
// 4 MiB for small messages with even denser encodings. A message of the default
// maximum message size of the client and server (64 MiB) is limited to 512 MiB of
// values. Raise MaxMemory if you raise the maximum message size, and expect messages
// that large. Set DefaultDecodingLimits before decoding begins.
var DefaultDecodingLimits = DecodingLimits{
	MaxMemory:          512 << 20,
	MinMemory:          4 << 20,
	MemoryPerInputByte: 32,
}

// DecodingLimitsProvider may be implemented by an EncodingContext to set the limits
// of the BinaryDecoders that use it, in place of DefaultDecodingLimits.
type DecodingLimitsProvider interface {
	DecodingLimits() DecodingLimits
}

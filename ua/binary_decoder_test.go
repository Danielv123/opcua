// Copyright 2021 Converter Systems LLC. All rights reserved.

package ua_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/awcullen/opcua/ua"
	"github.com/djherbis/buffer"
	"github.com/google/uuid"
	"gotest.tools/assert"
)

// maxTestAlloc is the most memory a decoder may allocate while rejecting one of
// the short, malformed inputs below.
const maxTestAlloc = 1 << 20

// le32 returns the little-endian encoding of an Int32.
func le32(v int32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(v))
	return b
}

// cat concatenates byte slices.
func cat(parts ...[]byte) []byte {
	return bytes.Join(parts, nil)
}

// opaqueReader hides the Len method of the underlying reader, so the decoder
// cannot tell how many bytes remain.
type opaqueReader struct {
	r io.Reader
}

func (r *opaqueReader) Read(p []byte) (int, error) {
	return r.r.Read(p)
}

// readerKinds returns the kinds of reader the decoder supports: a reader that
// reports its length as int, one that reports it as int64 (as used by the
// secure channels), and one that does not report its length at all.
func readerKinds(input []byte) map[string]io.Reader {
	partition := buffer.NewPartitionAt(buffer.NewMemPoolAt(64))
	if _, err := partition.Write(input); err != nil {
		panic(err)
	}
	return map[string]io.Reader{
		"bytes.Reader":    bytes.NewReader(input),
		"buffer.BufferAt": partition,
		"opaque":          &opaqueReader{bytes.NewReader(input)},
	}
}

// expectRejected decodes a malformed input with each kind of reader and checks
// that decoding fails without panicking and without allocating much memory.
func expectRejected(t *testing.T, input []byte, decode func(dec *ua.BinaryDecoder) error) {
	t.Helper()
	expectDecodeBounded(t, input, decode, true)
}

// expectDecodeBounded decodes an input with each kind of reader and checks that
// decoding does not panic or allocate much memory. If mustFail, or if the reader
// reports its length, decoding must fail.
func expectDecodeBounded(t *testing.T, input []byte, decode func(dec *ua.BinaryDecoder) error, mustFail bool) {
	t.Helper()
	for kind, r := range readerKinds(input) {
		dec := ua.NewBinaryDecoder(r, ua.NewEncodingContext())
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		err := func() (err error) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("%s: decoder panicked: %v", kind, r)
				}
			}()
			return decode(dec)
		}()
		runtime.ReadMemStats(&after)
		if err == nil && (mustFail || kind != "opaque") {
			t.Fatalf("%s: expected an error decoding malformed input", kind)
		}
		if n := after.TotalAlloc - before.TotalAlloc; n > maxTestAlloc {
			t.Fatalf("%s: decoder allocated %d bytes for a %d byte input", kind, n, len(input))
		}
	}
}

func TestDecodeStringLengthExceedsInput(t *testing.T) {
	cases := map[string][]byte{
		"max int32 length": cat(le32(0x7FFFFFFF), []byte("abc")),
		"1 MiB length":     cat(le32(1<<20), []byte("abc")),
		"one byte short":   cat(le32(4), []byte("abc")),
		"negative length":  cat(le32(-2), []byte("abc")),
		"min int32 length": cat(le32(-0x80000000), []byte("abc")),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			expectRejected(t, input, func(dec *ua.BinaryDecoder) error {
				var v string
				return dec.ReadString(&v)
			})
			expectRejected(t, input, func(dec *ua.BinaryDecoder) error {
				var v ua.ByteString
				return dec.ReadByteString(&v)
			})
			expectRejected(t, input, func(dec *ua.BinaryDecoder) error {
				var v ua.XMLElement
				return dec.ReadXMLElement(&v)
			})
			expectRejected(t, input, func(dec *ua.BinaryDecoder) error {
				var v []byte
				return dec.ReadByteArray(&v)
			})
			// a string inside a larger structure
			expectRejected(t, cat([]byte{0x02, 0x00}, input), func(dec *ua.BinaryDecoder) error {
				var v ua.QualifiedName
				return dec.ReadQualifiedName(&v)
			})
			expectRejected(t, cat([]byte{0x03}, input), func(dec *ua.BinaryDecoder) error {
				var v ua.LocalizedText
				return dec.ReadLocalizedText(&v)
			})
			expectRejected(t, cat([]byte{0x03, 0x01, 0x00}, input), func(dec *ua.BinaryDecoder) error {
				var v ua.NodeID
				return dec.ReadNodeID(&v)
			})
			expectRejected(t, cat([]byte{0x05, 0x01, 0x00}, input), func(dec *ua.BinaryDecoder) error {
				var v ua.NodeID
				return dec.ReadNodeID(&v)
			})
			expectRejected(t, cat([]byte{0x80, 0x00}, input), func(dec *ua.BinaryDecoder) error {
				var v ua.ExpandedNodeID
				return dec.ReadExpandedNodeID(&v)
			})
			expectRejected(t, cat([]byte{0x01, 0x0c}, input), func(dec *ua.BinaryDecoder) error {
				var v ua.DataValue
				if err := dec.ReadDataValue(&v); err != nil {
					return err
				}
				// ReadDataValue reports a bad value as a status code.
				if v.StatusCode == ua.Good {
					return nil
				}
				return v.StatusCode
			})
		})
	}
}

func TestDecodeNullAndEmptyStrings(t *testing.T) {
	cases := []struct {
		name  string
		input []byte
		want  string
	}{
		{"null", le32(-1), ""},
		{"empty", le32(0), ""},
		{"abc", cat(le32(3), []byte("abc")), "abc"},
	}
	for _, c := range cases {
		for kind, r := range readerKinds(c.input) {
			dec := ua.NewBinaryDecoder(r, ua.NewEncodingContext())
			var s string
			if err := dec.ReadString(&s); err != nil {
				t.Fatalf("%s/%s: %v", c.name, kind, err)
			}
			assert.Equal(t, s, c.want)
		}
		for kind, r := range readerKinds(c.input) {
			dec := ua.NewBinaryDecoder(r, ua.NewEncodingContext())
			var bs ua.ByteString
			if err := dec.ReadByteString(&bs); err != nil {
				t.Fatalf("%s/%s: %v", c.name, kind, err)
			}
			assert.Equal(t, string(bs), c.want)
		}
	}
}

func TestDecodeLargeStringRoundTrip(t *testing.T) {
	// larger than the decoder's initial allocation for inputs of unknown length.
	want := string(bytes.Repeat([]byte("0123456789abcdef"), 64*1024))
	buf := &bytes.Buffer{}
	enc := ua.NewBinaryEncoder(buf, ua.NewEncodingContext())
	if err := enc.WriteString(want); err != nil {
		t.Fatal(err)
	}
	for kind, r := range readerKinds(buf.Bytes()) {
		dec := ua.NewBinaryDecoder(r, ua.NewEncodingContext())
		var got string
		if err := dec.ReadString(&got); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if got != want {
			t.Fatalf("%s: string did not round trip", kind)
		}
	}
}

func TestDecodeArrayLengthExceedsInput(t *testing.T) {
	readers := map[string]func(dec *ua.BinaryDecoder) error{
		"Boolean":        func(dec *ua.BinaryDecoder) error { var v []bool; return dec.ReadBooleanArray(&v) },
		"SByte":          func(dec *ua.BinaryDecoder) error { var v []int8; return dec.ReadSByteArray(&v) },
		"Byte":           func(dec *ua.BinaryDecoder) error { var v []byte; return dec.ReadByteArray(&v) },
		"Int16":          func(dec *ua.BinaryDecoder) error { var v []int16; return dec.ReadInt16Array(&v) },
		"UInt16":         func(dec *ua.BinaryDecoder) error { var v []uint16; return dec.ReadUInt16Array(&v) },
		"Int32":          func(dec *ua.BinaryDecoder) error { var v []int32; return dec.ReadInt32Array(&v) },
		"UInt32":         func(dec *ua.BinaryDecoder) error { var v []uint32; return dec.ReadUInt32Array(&v) },
		"Int64":          func(dec *ua.BinaryDecoder) error { var v []int64; return dec.ReadInt64Array(&v) },
		"UInt64":         func(dec *ua.BinaryDecoder) error { var v []uint64; return dec.ReadUInt64Array(&v) },
		"Float":          func(dec *ua.BinaryDecoder) error { var v []float32; return dec.ReadFloatArray(&v) },
		"Double":         func(dec *ua.BinaryDecoder) error { var v []float64; return dec.ReadDoubleArray(&v) },
		"String":         func(dec *ua.BinaryDecoder) error { var v []string; return dec.ReadStringArray(&v) },
		"DateTime":       func(dec *ua.BinaryDecoder) error { var v []time.Time; return dec.ReadDateTimeArray(&v) },
		"GUID":           func(dec *ua.BinaryDecoder) error { var v []uuid.UUID; return dec.ReadGUIDArray(&v) },
		"ByteString":     func(dec *ua.BinaryDecoder) error { var v []ua.ByteString; return dec.ReadByteStringArray(&v) },
		"XMLElement":     func(dec *ua.BinaryDecoder) error { var v []ua.XMLElement; return dec.ReadXMLElementArray(&v) },
		"NodeID":         func(dec *ua.BinaryDecoder) error { var v []ua.NodeID; return dec.ReadNodeIDArray(&v) },
		"ExpandedNodeID": func(dec *ua.BinaryDecoder) error { var v []ua.ExpandedNodeID; return dec.ReadExpandedNodeIDArray(&v) },
		"StatusCode":     func(dec *ua.BinaryDecoder) error { var v []ua.StatusCode; return dec.ReadStatusCodeArray(&v) },
		"QualifiedName":  func(dec *ua.BinaryDecoder) error { var v []ua.QualifiedName; return dec.ReadQualifiedNameArray(&v) },
		"LocalizedText":  func(dec *ua.BinaryDecoder) error { var v []ua.LocalizedText; return dec.ReadLocalizedTextArray(&v) },
		"ExtensionObject": func(dec *ua.BinaryDecoder) error {
			var v []ua.ExtensionObject
			return dec.ReadExtensionObjectArray(&v)
		},
		"DataValue": func(dec *ua.BinaryDecoder) error { var v []ua.DataValue; return dec.ReadDataValueArray(&v) },
		"Variant":   func(dec *ua.BinaryDecoder) error { var v []ua.Variant; return dec.ReadVariantArray(&v) },
		"DiagnosticInfo": func(dec *ua.BinaryDecoder) error {
			var v []ua.DiagnosticInfo
			return dec.ReadDiagnosticInfoArray(&v)
		},
		// arrays decoded by reflection
		"[]ReadValueID": func(dec *ua.BinaryDecoder) error { var v []ua.ReadValueID; return dec.Decode(&v) },
		"[]WriteValue":  func(dec *ua.BinaryDecoder) error { var v []ua.WriteValue; return dec.Decode(&v) },
		"[]string":      func(dec *ua.BinaryDecoder) error { var v []string; return dec.Decode(&v) },
		"ReadRequest":   func(dec *ua.BinaryDecoder) error { var v ua.ReadRequest; return dec.Decode(&v) },
	}
	lengths := map[string][]byte{
		"max int32 length": le32(0x7FFFFFFF),
		"64 Mi elements":   le32(64 << 20),
		"negative length":  le32(-2),
		"min int32 length": le32(-0x80000000),
	}
	// a short tail, which is a valid encoding of a few null or zero elements of every type.
	tail := make([]byte, 32)
	// a ReadRequest, whose last field is the NodesToRead array.
	req := &bytes.Buffer{}
	if err := ua.NewBinaryEncoder(req, ua.NewEncodingContext()).Encode(&ua.ReadRequest{}); err != nil {
		t.Fatal(err)
	}
	reqPrefix := req.Bytes()[:req.Len()-4]
	for name, read := range readers {
		for lname, length := range lengths {
			input := cat(length, tail)
			if name == "ReadRequest" {
				input = cat(reqPrefix, length, tail)
			}
			t.Run(name+"/"+lname, func(t *testing.T) {
				expectRejected(t, input, read)
			})
		}
	}
}

func TestDecodeNullAndEmptyArrays(t *testing.T) {
	for kind, r := range readerKinds(cat(le32(-1), le32(0))) {
		dec := ua.NewBinaryDecoder(r, ua.NewEncodingContext())
		var v []int32
		if err := dec.ReadInt32Array(&v); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if v != nil {
			t.Fatalf("%s: expected a nil array", kind)
		}
		if err := dec.ReadInt32Array(&v); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if v == nil || len(v) != 0 {
			t.Fatalf("%s: expected an empty array", kind)
		}
	}
}

func TestDecodeLargeArrayRoundTrip(t *testing.T) {
	// larger than the decoder's initial allocation for arrays.
	ints := make([]int32, 100_000)
	for i := range ints {
		ints[i] = int32(i)
	}
	dvs := make([]ua.DataValue, 10_000)
	for i := range dvs {
		dvs[i] = ua.NewDataValue(int32(i), ua.Good, time.Time{}, 0, time.Time{}, 0)
	}
	rvs := make([]ua.ReadValueID, 10_000)
	for i := range rvs {
		rvs[i] = ua.ReadValueID{NodeID: ua.NewNodeIDNumeric(1, uint32(i)), AttributeID: ua.AttributeIDValue}
	}
	buf := &bytes.Buffer{}
	enc := ua.NewBinaryEncoder(buf, ua.NewEncodingContext())
	if err := enc.WriteInt32Array(ints); err != nil {
		t.Fatal(err)
	}
	if err := enc.WriteDataValueArray(dvs); err != nil {
		t.Fatal(err)
	}
	if err := enc.Encode(rvs); err != nil {
		t.Fatal(err)
	}
	for kind, r := range readerKinds(buf.Bytes()) {
		dec := ua.NewBinaryDecoder(r, ua.NewEncodingContext())
		var ints2 []int32
		if err := dec.ReadInt32Array(&ints2); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		assert.DeepEqual(t, ints2, ints)
		var dvs2 []ua.DataValue
		if err := dec.ReadDataValueArray(&dvs2); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		assert.DeepEqual(t, dvs2, dvs)
		var rvs2 []ua.ReadValueID
		if err := dec.Decode(&rvs2); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		assert.DeepEqual(t, rvs2, rvs)
	}
}

func TestDecodeVariantArrayLengthExceedsInput(t *testing.T) {
	tail := make([]byte, 32)
	for typ := byte(1); typ <= 25; typ++ {
		for _, mask := range []byte{0x80, 0xC0} {
			input := cat([]byte{mask | typ}, le32(0x7FFFFFFF), tail)
			expectRejected(t, input, func(dec *ua.BinaryDecoder) error {
				var v ua.Variant
				return dec.ReadVariant(&v)
			})
		}
	}
}

func TestDecodeVariantArrayDimensions(t *testing.T) {
	cases := map[string][]byte{
		// 2 values, dimensions declare 1x1
		"product too small": cat([]byte{0xC6}, le32(2), le32(1), le32(2), le32(2), le32(1), le32(1)),
		// 2 values, dimensions declare 2x2
		"product too large": cat([]byte{0xC6}, le32(2), le32(1), le32(2), le32(2), le32(2), le32(2)),
		// 2 values, dimensions declare -1x-2
		"negative dimensions": cat([]byte{0xC6}, le32(2), le32(1), le32(2), le32(2), le32(-1), le32(-2)),
		// 2 values, dimensions overflow int32 and int64 when multiplied
		"overflowing dimensions": cat([]byte{0xC6}, le32(2), le32(1), le32(2), le32(3), le32(0x7FFFFFFF), le32(0x7FFFFFFF), le32(0x7FFFFFFF)),
		// 0 values, but dimensions that ask for billions of empty rows
		"huge empty 2D array": cat([]byte{0xC1}, le32(0), le32(2), le32(0x7FFFFFFF), le32(0)),
		"huge empty 3D array": cat([]byte{0xC1}, le32(0), le32(3), le32(0x10000), le32(0x10000), le32(0)),
		// one dimension
		"rank 1": cat([]byte{0xC6}, le32(2), le32(1), le32(2), le32(1), le32(2)),
		// missing dimensions
		"null dimensions": cat([]byte{0xC6}, le32(2), le32(1), le32(2), le32(-1)),
		// huge dimension count
		"dimension count exceeds input": cat([]byte{0xC6}, le32(2), le32(1), le32(2), le32(0x7FFFFFFF), le32(1), le32(2)),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			expectRejected(t, input, func(dec *ua.BinaryDecoder) error {
				var v ua.Variant
				return dec.ReadVariant(&v)
			})
		})
	}
}

func TestDecodeVariantMatrixRoundTrip(t *testing.T) {
	cases := []ua.Variant{
		[][]int32{{1, 2, 3}, {4, 5, 6}},
		[][]string{{"a", "b"}, {"c", "d"}, {"e", "f"}},
		[][]bool{{}, {}, {}},
		[][][]float64{{{1, 2}, {3, 4}}, {{5, 6}, {7, 8}}, {{9, 10}, {11, 12}}},
		[][][]byte{{{}, {}}},
		[][]ua.Variant{{int32(1), "x"}, {nil, true}},
	}
	for _, in := range cases {
		buf := &bytes.Buffer{}
		enc := ua.NewBinaryEncoder(buf, ua.NewEncodingContext())
		if err := enc.WriteVariant(in); err != nil {
			t.Fatal(err)
		}
		for kind, r := range readerKinds(buf.Bytes()) {
			dec := ua.NewBinaryDecoder(r, ua.NewEncodingContext())
			var out ua.Variant
			if err := dec.ReadVariant(&out); err != nil {
				t.Fatalf("%s: %T: %v", kind, in, err)
			}
			assert.DeepEqual(t, out, in)
		}
	}
}

func TestDecodeExtensionObjectBodyLengthExceedsInput(t *testing.T) {
	// RequestHeader binary encoding id (i=391), binary body, declared body length.
	prefix := []byte{0x01, 0x00, 0x87, 0x01, 0x01}
	cases := map[string][]byte{
		"known type":   cat(prefix, le32(0x7FFFFFFF), make([]byte, 40)),
		"unknown type": cat([]byte{0x01, 0x00, 0xff, 0xff, 0x01}, le32(0x7FFFFFFF), make([]byte, 40)),
		"xml body":     cat([]byte{0x00, 0x00, 0x02}, le32(0x7FFFFFFF), make([]byte, 40)),
		"negative":     cat(prefix, le32(-2), make([]byte, 40)),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			// the body of a known type is decoded by its type, so its declared length
			// can only be checked if the length of the input is known.
			expectDecodeBounded(t, input, func(dec *ua.BinaryDecoder) error {
				var v ua.ExtensionObject
				return dec.ReadExtensionObject(&v)
			}, name != "known type")
		})
	}
}

func TestDecodeNestingLimit(t *testing.T) {
	const depth = 10_000
	cases := map[string][]byte{
		// Variant containing a Variant containing a Variant...
		"variant": cat(bytes.Repeat([]byte{0x18}, depth), []byte{0x00}),
		// Variant containing an array of one Variant containing...
		"variant array": cat(bytes.Repeat(cat([]byte{0x98}, le32(1)), depth), []byte{0x00}),
		// Variant containing a matrix of one Variant containing...
		"variant matrix": cat(bytes.Repeat(cat([]byte{0xD8}, le32(1)), depth), []byte{0x00}, bytes.Repeat(cat(le32(2), le32(1), le32(1)), depth)),
		// Variant containing a DataValue containing a Variant...
		"data value": cat(bytes.Repeat([]byte{0x17, 0x01}, depth), []byte{0x00}),
		// array of DataValues, the first containing a DataValue containing a Variant...
		"data value array": cat([]byte{0x97}, le32(2), bytes.Repeat([]byte{0x01, 0x17}, depth), []byte{0x00, 0x00}),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			read := func(dec *ua.BinaryDecoder) error {
				var v ua.Variant
				return dec.ReadVariant(&v)
			}
			expectRejected(t, input, read)
			dec := ua.NewBinaryDecoder(bytes.NewReader(input), ua.NewEncodingContext())
			if err := read(dec); !errors.Is(err, ua.BadEncodingLimitsExceeded) && !errors.Is(err, ua.BadDecodingError) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}

	// a DataValue reports a Variant it cannot decode as BadDataTypeIDUnknown, but
	// not one that is nested too deeply.
	input := cat(bytes.Repeat([]byte{0x01, 0x17}, depth), []byte{0x00})
	dec := ua.NewBinaryDecoder(bytes.NewReader(input), ua.NewEncodingContext())
	var dv ua.DataValue
	if err := dec.ReadDataValue(&dv); !errors.Is(err, ua.BadEncodingLimitsExceeded) {
		t.Fatalf("expected BadEncodingLimitsExceeded, got %v", err)
	}
}

func TestDecodeModerateNesting(t *testing.T) {
	// nesting well within the limit decodes.
	var v ua.Variant = int32(7)
	for i := 0; i < 20; i++ {
		v = []ua.DataValue{ua.NewDataValue([]ua.Variant{v}, ua.Good, time.Time{}, 0, time.Time{}, 0)}
	}
	buf := &bytes.Buffer{}
	enc := ua.NewBinaryEncoder(buf, ua.NewEncodingContext())
	if err := enc.WriteVariant(v); err != nil {
		t.Fatal(err)
	}
	encoded := buf.Bytes()

	dec := ua.NewBinaryDecoder(buf, ua.NewEncodingContext())
	var out ua.Variant
	if err := dec.ReadVariant(&out); err != nil {
		t.Fatal(err)
	}
	// go-cmp is slow to compare deeply nested slices.
	if !reflect.DeepEqual(out, v) {
		t.Fatal("value did not round trip")
	}

	// the decoder can be used again after rejecting deeply nested input.
	buf.Reset()
	buf.Write(cat(bytes.Repeat([]byte{0x18}, 1000), []byte{0x00}))
	if err := dec.ReadVariant(&out); err == nil {
		t.Fatal("expected an error decoding deeply nested input")
	}
	buf.Reset()
	buf.Write(encoded)
	if err := dec.ReadVariant(&out); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(out, v) {
		t.Fatal("value did not round trip")
	}
}

func TestDecodeGrowingInput(t *testing.T) {
	// an input that reports its length as int64 is sampled, and sampled again
	// when it may have grown.
	long := strings.Repeat("x", 100*1024)
	partition := buffer.NewPartitionAt(buffer.NewMemPoolAt(1024))
	enc := ua.NewBinaryEncoder(partition, ua.NewEncodingContext())
	if err := enc.WriteString(long); err != nil {
		t.Fatal(err)
	}
	dec := ua.NewBinaryDecoder(partition, ua.NewEncodingContext())
	var s string
	if err := dec.ReadString(&s); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, s, long)
	if err := enc.WriteString("abc"); err != nil {
		t.Fatal(err)
	}
	if err := dec.ReadString(&s); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, s, "abc")

	// an input that reports its length as int is not sampled.
	buf := &bytes.Buffer{}
	enc = ua.NewBinaryEncoder(buf, ua.NewEncodingContext())
	dec = ua.NewBinaryDecoder(buf, ua.NewEncodingContext())
	for _, want := range []string{"abc", "defg", long} {
		if err := enc.WriteString(want); err != nil {
			t.Fatal(err)
		}
		if err := dec.ReadString(&s); err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, s, want)
	}
}

// Copyright 2021 Converter Systems LLC. All rights reserved.

package ua_test

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/awcullen/opcua/ua"
	"github.com/djherbis/buffer"
	"gotest.tools/assert"
)

// historyUpdateRequest returns a HistoryUpdateRequest that updates a node with n
// empty DataValues, each of which is encoded in one byte, but takes 88 bytes.
func historyUpdateRequest(t *testing.T, n int) []byte {
	t.Helper()
	// encode a request with an empty UpdateValues array, which ends the request.
	req := ua.HistoryUpdateRequest{
		HistoryUpdateDetails: []ua.ExtensionObject{ua.UpdateDataDetails{UpdateValues: []ua.DataValue{}}},
	}
	buf := buffer.NewPartitionAt(buffer.NewMemPoolAt(4096))
	if err := ua.NewBinaryEncoder(buf, ua.NewEncodingContext()).Encode(&req); err != nil {
		t.Fatal(err)
	}
	encoded := make([]byte, buf.Len())
	if _, err := buf.Read(encoded); err != nil {
		t.Fatal(err)
	}
	// the body of the UpdateDataDetails: a null NodeID, PerformInsertReplace, and the
	// length of UpdateValues.
	const body = 2 + 4 + 4
	prefix := encoded[:len(encoded)-body-4]
	if !bytes.Equal(encoded[len(encoded)-body-4:], cat(le32(body), []byte{0, 0}, le32(0), le32(0))) {
		t.Fatalf("unexpected encoding % x", encoded)
	}
	return cat(prefix, le32(int32(body+n)), []byte{0, 0}, le32(0), le32(int32(n)), make([]byte, n))
}

// decodeWithStats decodes the input and returns the error and the memory allocated.
func decodeWithStats(t *testing.T, r interface{ Read([]byte) (int, error) }, ec ua.EncodingContext, decode func(*ua.BinaryDecoder) error) (error, uint64) {
	t.Helper()
	dec := ua.NewBinaryDecoder(r, ec)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	err := decode(dec)
	runtime.ReadMemStats(&after)
	return err, after.TotalAlloc - before.TotalAlloc
}

func TestDecodeMemoryLimitRejectsAmplification(t *testing.T) {
	// 4 MiB of DataValues would take 352 MiB of memory, but may take 4 MiB plus
	// 32 bytes per byte of input, or 132 MiB.
	input := historyUpdateRequest(t, 4<<20)
	for kind, r := range readerKinds(input) {
		err, allocated := decodeWithStats(t, r, ua.NewEncodingContext(), func(dec *ua.BinaryDecoder) error {
			var req ua.HistoryUpdateRequest
			return dec.Decode(&req)
		})
		if !errors.Is(err, ua.BadEncodingLimitsExceeded) {
			t.Fatalf("%s: expected BadEncodingLimitsExceeded, got %v", kind, err)
		}
		// if the length of the input is known, the array is rejected before memory is
		// allocated for it. Otherwise, it is rejected once it takes more than the limit
		// for the input read so far.
		limit := uint64(1 << 20)
		if kind == "opaque" {
			limit = 8 << 20
		}
		if allocated > limit {
			t.Fatalf("%s: decoder allocated %d bytes", kind, allocated)
		}
	}
}

func TestDecodeMemoryLimitAbsolute(t *testing.T) {
	// limits that allow plenty of memory per byte of input, but little in total.
	ec := limitsContext{ua.DecodingLimits{MaxMemory: 1 << 20, MemoryPerInputByte: 1000}}
	input := historyUpdateRequest(t, 100_000)
	for kind, r := range readerKinds(input) {
		err, _ := decodeWithStats(t, r, ec, func(dec *ua.BinaryDecoder) error {
			var req ua.HistoryUpdateRequest
			return dec.Decode(&req)
		})
		if !errors.Is(err, ua.BadEncodingLimitsExceeded) {
			t.Fatalf("%s: expected BadEncodingLimitsExceeded, got %v", kind, err)
		}
	}
}

// limitsContext is an EncodingContext that provides DecodingLimits.
type limitsContext struct {
	limits ua.DecodingLimits
}

func (c limitsContext) NamespaceURIs() []string {
	return []string{"http://opcfoundation.org/UA/"}
}

func (c limitsContext) DecodingLimits() ua.DecodingLimits {
	return c.limits
}

func TestDecodeMemoryLimitConfigurable(t *testing.T) {
	// 100,000 empty DataValues take 8.8 MB, more than the default limits allow for
	// 100 kB of input, but not more than no limits.
	input := historyUpdateRequest(t, 100_000)
	for _, c := range []struct {
		name string
		ec   ua.EncodingContext
		want error
	}{
		{"default", ua.NewEncodingContext(), ua.BadEncodingLimitsExceeded},
		{"no limits", limitsContext{}, nil},
		{"higher limits", limitsContext{ua.DecodingLimits{MaxMemory: 1 << 30, MemoryPerInputByte: 100}}, nil},
	} {
		for kind, r := range readerKinds(input) {
			dec := ua.NewBinaryDecoder(r, c.ec)
			var req ua.HistoryUpdateRequest
			err := dec.Decode(&req)
			if !errors.Is(err, c.want) && !(err == nil && c.want == nil) {
				t.Fatalf("%s/%s: expected %v, got %v", c.name, kind, c.want, err)
			}
			if err == nil {
				values := req.HistoryUpdateDetails[0].(ua.UpdateDataDetails).UpdateValues
				if len(values) != 100_000 {
					t.Fatalf("%s/%s: decoded %d values", c.name, kind, len(values))
				}
			}
		}
	}
}

func TestDecodeMemoryLimitErrors(t *testing.T) {
	// decoding limits are reported as BadEncodingLimitsExceeded by the functions
	// that decode an outermost value, even where a contained value fails with
	// BadDecodingError.
	const n = 1_000_000
	dataValues := cat(le32(n), make([]byte, n))
	variant := cat([]byte{0x98}, le32(1), []byte{0x97}, dataValues)
	dataValue := cat([]byte{0x01, 0x98}, le32(1), []byte{0x97}, dataValues)
	cases := map[string]struct {
		input  []byte
		decode func(*ua.BinaryDecoder) error
	}{
		"ReadDataValueArray": {dataValues, func(dec *ua.BinaryDecoder) error { var v []ua.DataValue; return dec.ReadDataValueArray(&v) }},
		"Decode":             {dataValues, func(dec *ua.BinaryDecoder) error { var v []ua.DataValue; return dec.Decode(&v) }},
		"ReadVariant":        {variant, func(dec *ua.BinaryDecoder) error { var v ua.Variant; return dec.ReadVariant(&v) }},
		"ReadDataValue":      {dataValue, func(dec *ua.BinaryDecoder) error { var v ua.DataValue; return dec.ReadDataValue(&v) }},
		"ReadVariantArray": {cat(le32(1), variant), func(dec *ua.BinaryDecoder) error {
			var v []ua.Variant
			return dec.ReadVariantArray(&v)
		}},
	}
	for name, c := range cases {
		dec := ua.NewBinaryDecoder(bytes.NewReader(c.input), ua.NewEncodingContext())
		if err := c.decode(dec); !errors.Is(err, ua.BadEncodingLimitsExceeded) {
			t.Fatalf("%s: expected BadEncodingLimitsExceeded, got %v", name, err)
		}
	}
}

func TestDecodeMemoryLimitIsStrict(t *testing.T) {
	// a limit is not exceeded by memory allocated before elements are decoded, even
	// if the length of the input is unknown.
	ec := limitsContext{ua.DecodingLimits{MaxMemory: 1}}
	for kind, r := range readerKinds(cat(le32(0x7FFFFFFF), make([]byte, 64))) {
		err, allocated := decodeWithStats(t, r, ec, func(dec *ua.BinaryDecoder) error {
			var v []ua.DataValue
			return dec.ReadDataValueArray(&v)
		})
		if kind != "opaque" {
			// the array is longer than the input.
			continue
		}
		if !errors.Is(err, ua.BadEncodingLimitsExceeded) {
			t.Fatalf("%s: expected BadEncodingLimitsExceeded, got %v", kind, err)
		}
		if allocated > 16<<10 {
			t.Fatalf("%s: decoder allocated %d bytes", kind, allocated)
		}
	}
	for kind, r := range readerKinds(cat(le32(0x7FFFFFFF), make([]byte, 64))) {
		err, allocated := decodeWithStats(t, r, ec, func(dec *ua.BinaryDecoder) error {
			var v []ua.ReadValueID
			return dec.Decode(&v)
		})
		if kind != "opaque" {
			continue
		}
		if !errors.Is(err, ua.BadEncodingLimitsExceeded) {
			t.Fatalf("%s: expected BadEncodingLimitsExceeded, got %v", kind, err)
		}
		if allocated > 16<<10 {
			t.Fatalf("%s: decoder allocated %d bytes", kind, allocated)
		}
	}
}

func TestDecodeMemoryLimitPerInputByteOnly(t *testing.T) {
	// with no minimum, values that take no more memory than their encoding decode
	// from any reader, even if the length of the input is unknown.
	ec := limitsContext{ua.DecodingLimits{MaxMemory: 1 << 20, MemoryPerInputByte: 1}}
	long := bytes.Repeat([]byte("0123456789"), 10_000)
	cases := map[string]struct {
		input  []byte
		decode func(*ua.BinaryDecoder) (any, error)
		want   any
	}{
		"short String": {cat(le32(5), []byte("hello")), func(dec *ua.BinaryDecoder) (any, error) {
			var v string
			err := dec.ReadString(&v)
			return v, err
		}, "hello"},
		"long String": {cat(le32(int32(len(long))), long), func(dec *ua.BinaryDecoder) (any, error) {
			var v string
			err := dec.ReadString(&v)
			return v, err
		}, string(long)},
		"ByteString": {cat(le32(int32(len(long))), long), func(dec *ua.BinaryDecoder) (any, error) {
			var v ua.ByteString
			err := dec.ReadByteString(&v)
			return v, err
		}, ua.ByteString(long)},
		"ByteArray": {cat(le32(int32(len(long))), long), func(dec *ua.BinaryDecoder) (any, error) {
			var v []byte
			err := dec.ReadByteArray(&v)
			return v, err
		}, long},
		"empty ByteArray": {le32(0), func(dec *ua.BinaryDecoder) (any, error) {
			var v []byte
			err := dec.ReadByteArray(&v)
			return v, err
		}, []byte{}},
	}
	for name, c := range cases {
		for kind, r := range readerKinds(c.input) {
			got, err := c.decode(ua.NewBinaryDecoder(r, ec))
			if err != nil {
				t.Fatalf("%s/%s: %v", name, kind, err)
			}
			assert.DeepEqual(t, got, c.want)
		}
	}

	// arrays of unknown length need a little more memory, for the list of chunks they
	// are decoded in.
	ec = limitsContext{ua.DecodingLimits{MaxMemory: 1 << 20, MinMemory: 1024, MemoryPerInputByte: 2}}
	for kind, r := range readerKinds(cat(le32(int32(len(long))), bytes.Repeat([]byte{1}, len(long)))) {
		var v []bool
		if err := ua.NewBinaryDecoder(r, ec).ReadBooleanArray(&v); err != nil {
			t.Fatalf("Boolean array/%s: %v", kind, err)
		}
		if len(v) != len(long) {
			t.Fatalf("Boolean array/%s: decoded %d elements", kind, len(v))
		}
	}
}

func TestDecodeMemoryLimitChunksAreFew(t *testing.T) {
	// a value of unknown length is decoded in few chunks, even if the limits allow
	// little more memory than the input.
	ec := limitsContext{ua.DecodingLimits{MaxMemory: 2 << 20, MemoryPerInputByte: 1}}
	const n = 1 << 20
	input := cat(le32(n), make([]byte, n))
	r := &opaqueReader{bytes.NewReader(input)}
	dec := ua.NewBinaryDecoder(r, ec)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	var v []byte
	if err := dec.ReadByteArray(&v); err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	if len(v) != n {
		t.Fatalf("decoded %d bytes", len(v))
	}
	// the chunks, the list of chunks, and the joined value.
	if a := after.TotalAlloc - before.TotalAlloc; a > 3*n {
		t.Fatalf("decoder allocated %d bytes", a)
	}
	if m := after.Mallocs - before.Mallocs; m > n/4096+100 {
		t.Fatalf("decoder allocated %d times", m)
	}
}

func TestDecodeMemoryLimitGrowingInput(t *testing.T) {
	// the memory allowed grows with an input that reports its length as int64 and
	// grows between values.
	ec := limitsContext{ua.DecodingLimits{MaxMemory: 1 << 20, MemoryPerInputByte: 10}}
	partition := buffer.NewPartitionAt(buffer.NewMemPoolAt(1024))
	dec := ua.NewBinaryDecoder(partition, ec)
	partition.Write(cat(le32(1), []byte("a")))
	var s string
	if err := dec.ReadString(&s); err != nil {
		t.Fatal(err)
	}
	// a DataValue takes 88 bytes, which the 17 bytes of input allow, but not the 6
	// bytes read when its Variant is decoded.
	partition.Write(cat([]byte{0x17, 0x00}, le32(6), []byte("abcdef")))
	var v ua.Variant
	if err := dec.ReadVariant(&v); err != nil {
		t.Fatal(err)
	}
	if err := dec.ReadString(&s); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, s, "abcdef")
}

func TestDecodeLargeElementsOfUnknownLength(t *testing.T) {
	// an array of elements larger than maxPreallocBytes decodes from an input of
	// unknown length.
	fields := make([]reflect.StructField, 9000)
	for i := range fields {
		fields[i] = reflect.StructField{Name: fmt.Sprintf("F%d", i), Type: reflect.TypeOf(int64(0))}
	}
	typ := reflect.SliceOf(reflect.StructOf(fields))
	input := cat(le32(2), make([]byte, 2*9000*8))
	for kind, r := range readerKinds(input) {
		v := reflect.New(typ)
		done := make(chan error, 1)
		go func() {
			done <- ua.NewBinaryDecoder(r, ua.NewEncodingContext()).Decode(v.Interface())
		}()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("%s: %v", kind, err)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: decoding did not finish", kind)
		}
		if n := v.Elem().Len(); n != 2 {
			t.Fatalf("%s: decoded %d elements", kind, n)
		}
	}
}

func TestDecodeMemoryLimitErrorsOfCompositeValues(t *testing.T) {
	// values that contain Strings or ByteStrings report the limit being exceeded.
	ec := limitsContext{ua.DecodingLimits{MaxMemory: 1}}
	str := cat(le32(2), []byte("xx"))
	cases := map[string]struct {
		input  []byte
		decode func(*ua.BinaryDecoder) error
	}{
		"string NodeID":         {cat([]byte{0x03, 0x00, 0x00}, str), func(dec *ua.BinaryDecoder) error { var v ua.NodeID; return dec.ReadNodeID(&v) }},
		"opaque NodeID":         {cat([]byte{0x05, 0x00, 0x00}, str), func(dec *ua.BinaryDecoder) error { var v ua.NodeID; return dec.ReadNodeID(&v) }},
		"string ExpandedNodeID": {cat([]byte{0x03, 0x00, 0x00}, str), func(dec *ua.BinaryDecoder) error { var v ua.ExpandedNodeID; return dec.ReadExpandedNodeID(&v) }},
		"namespace URI":         {cat([]byte{0x80, 0x01}, str), func(dec *ua.BinaryDecoder) error { var v ua.ExpandedNodeID; return dec.ReadExpandedNodeID(&v) }},
		"QualifiedName":         {cat([]byte{0x00, 0x00}, str), func(dec *ua.BinaryDecoder) error { var v ua.QualifiedName; return dec.ReadQualifiedName(&v) }},
		"LocalizedText locale":  {cat([]byte{0x01}, str), func(dec *ua.BinaryDecoder) error { var v ua.LocalizedText; return dec.ReadLocalizedText(&v) }},
		"LocalizedText text":    {cat([]byte{0x02}, str), func(dec *ua.BinaryDecoder) error { var v ua.LocalizedText; return dec.ReadLocalizedText(&v) }},
		"XMLElement":            {str, func(dec *ua.BinaryDecoder) error { var v ua.XMLElement; return dec.ReadXMLElement(&v) }},
		"ByteArray":             {str, func(dec *ua.BinaryDecoder) error { var v []byte; return dec.ReadByteArray(&v) }},
	}
	for name, c := range cases {
		for kind, r := range readerKinds(c.input) {
			dec := ua.NewBinaryDecoder(r, ec)
			if err := c.decode(dec); !errors.Is(err, ua.BadEncodingLimitsExceeded) {
				t.Fatalf("%s/%s: expected BadEncodingLimitsExceeded, got %v", name, kind, err)
			}
		}
	}
}

func TestDecodeMemoryLimitAllowsRealisticMessages(t *testing.T) {
	now := time.Date(2026, time.October, 1, 12, 0, 0, 0, time.UTC)
	values := func(n int, f func(i int) ua.DataValue) []ua.DataValue {
		v := make([]ua.DataValue, n)
		for i := range v {
			v[i] = f(i)
		}
		return v
	}
	cases := map[string]any{
		// a large Read response of doubles with source timestamps.
		"doubles": &ua.ReadResponse{Results: values(200_000, func(i int) ua.DataValue {
			return ua.NewDataValue(float64(i), ua.Good, now, 0, time.Time{}, 0)
		})},
		// a large Read response of status codes only, about 18 bytes per byte.
		"status codes": &ua.ReadResponse{Results: values(300_000, func(i int) ua.DataValue {
			return ua.NewDataValue(nil, ua.BadNodeIDUnknown, time.Time{}, 0, time.Time{}, 0)
		})},
		// a large Read response of Booleans without timestamps, about 30 bytes per byte.
		"booleans": &ua.ReadResponse{Results: values(300_000, func(i int) ua.DataValue {
			return ua.NewDataValue(i%2 == 0, ua.Good, time.Time{}, 0, time.Time{}, 0)
		})},
		// a large ByteString, which takes as much memory as its encoding.
		"byte string": &ua.WriteRequest{NodesToWrite: []ua.WriteValue{{
			NodeID:      ua.NewNodeIDNumeric(2, 1),
			AttributeID: ua.AttributeIDValue,
			Value:       ua.NewDataValue(ua.ByteString(bytes.Repeat([]byte{1, 2, 3, 4}, 4<<20)), ua.Good, now, 0, now, 0),
		}}},
	}
	for name, in := range cases {
		buf := &bytes.Buffer{}
		if err := ua.NewBinaryEncoder(buf, ua.NewEncodingContext()).Encode(in); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		input := buf.Bytes()
		for kind, r := range readerKinds(input) {
			var err error
			switch in.(type) {
			case *ua.ReadResponse:
				var out ua.ReadResponse
				if err = ua.NewBinaryDecoder(r, ua.NewEncodingContext()).Decode(&out); err == nil && len(out.Results) != len(in.(*ua.ReadResponse).Results) {
					t.Fatalf("%s/%s: decoded %d results", name, kind, len(out.Results))
				}
			case *ua.WriteRequest:
				var out ua.WriteRequest
				if err = ua.NewBinaryDecoder(r, ua.NewEncodingContext()).Decode(&out); err == nil && len(out.NodesToWrite[0].Value.Value.(ua.ByteString)) != 16<<20 {
					t.Fatalf("%s/%s: decoded a ByteString of the wrong length", name, kind)
				}
			}
			if err != nil {
				t.Fatalf("%s/%s: %v", name, kind, err)
			}
		}
	}
}

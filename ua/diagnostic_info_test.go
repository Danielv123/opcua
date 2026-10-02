// Copyright 2021 Converter Systems LLC. All rights reserved.

package ua_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/awcullen/opcua/ua"
	"gotest.tools/assert"
)

func int32Ptr(v int32) *int32 { return &v }

func stringPtr(v string) *string { return &v }

func statusCodePtr(v ua.StatusCode) *ua.StatusCode { return &v }

func TestDiagnosticInfoRoundTrip(t *testing.T) {
	cases := map[string]struct {
		in    ua.DiagnosticInfo
		bytes []byte
	}{
		"empty": {
			ua.DiagnosticInfo{},
			[]byte{0x00},
		},
		"SymbolicID": {
			ua.DiagnosticInfo{SymbolicID: int32Ptr(0)},
			[]byte{0x01, 0x00, 0x00, 0x00, 0x00},
		},
		"NamespaceURI": {
			ua.DiagnosticInfo{NamespaceURI: int32Ptr(2)},
			[]byte{0x02, 0x02, 0x00, 0x00, 0x00},
		},
		"LocalizedText": {
			ua.DiagnosticInfo{LocalizedText: int32Ptr(3)},
			[]byte{0x04, 0x03, 0x00, 0x00, 0x00},
		},
		"Locale": {
			ua.DiagnosticInfo{Locale: int32Ptr(4)},
			[]byte{0x08, 0x04, 0x00, 0x00, 0x00},
		},
		"AdditionalInfo": {
			ua.DiagnosticInfo{AdditionalInfo: stringPtr("bar")},
			[]byte{0x10, 0x03, 0x00, 0x00, 0x00, 0x62, 0x61, 0x72},
		},
		"InnerStatusCode": {
			ua.DiagnosticInfo{InnerStatusCode: statusCodePtr(ua.BadNodeIDUnknown)},
			[]byte{0x20, 0x00, 0x00, 0x34, 0x80},
		},
		"InnerDiagnosticInfo": {
			ua.DiagnosticInfo{InnerDiagnosticInfo: &ua.DiagnosticInfo{SymbolicID: int32Ptr(5)}},
			[]byte{0x40, 0x01, 0x05, 0x00, 0x00, 0x00},
		},
		"all": {
			ua.DiagnosticInfo{
				SymbolicID:      int32Ptr(1),
				NamespaceURI:    int32Ptr(2),
				LocalizedText:   int32Ptr(3),
				Locale:          int32Ptr(4),
				AdditionalInfo:  stringPtr("bar"),
				InnerStatusCode: statusCodePtr(ua.BadNodeIDUnknown),
				InnerDiagnosticInfo: &ua.DiagnosticInfo{
					InnerDiagnosticInfo: &ua.DiagnosticInfo{AdditionalInfo: stringPtr("baz")},
				},
			},
			[]byte{
				0x7f,
				0x01, 0x00, 0x00, 0x00, // SymbolicID
				0x02, 0x00, 0x00, 0x00, // NamespaceURI
				0x04, 0x00, 0x00, 0x00, // Locale
				0x03, 0x00, 0x00, 0x00, // LocalizedText
				0x03, 0x00, 0x00, 0x00, 0x62, 0x61, 0x72, // AdditionalInfo
				0x00, 0x00, 0x34, 0x80, // InnerStatusCode
				0x40,                                           // InnerDiagnosticInfo
				0x10, 0x03, 0x00, 0x00, 0x00, 0x62, 0x61, 0x7a, // InnerDiagnosticInfo.InnerDiagnosticInfo
			},
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			enc := ua.NewBinaryEncoder(buf, ua.NewEncodingContext())
			if err := enc.WriteDiagnosticInfo(c.in); err != nil {
				t.Fatal(err)
			}
			assert.DeepEqual(t, buf.Bytes(), c.bytes)

			dec := ua.NewBinaryDecoder(bytes.NewReader(c.bytes), ua.NewEncodingContext())
			var out ua.DiagnosticInfo
			if err := dec.ReadDiagnosticInfo(&out); err != nil {
				t.Fatal(err)
			}
			assert.DeepEqual(t, out, c.in)

			// as a Variant
			dec = ua.NewBinaryDecoder(bytes.NewReader(cat([]byte{0x19}, c.bytes)), ua.NewEncodingContext())
			var v ua.Variant
			if err := dec.ReadVariant(&v); err != nil {
				t.Fatal(err)
			}
			assert.DeepEqual(t, v, ua.Variant(c.in))
		})
	}
}

func TestDiagnosticInfoMalformed(t *testing.T) {
	// each presence bit set, with the field it announces truncated or missing.
	cases := map[string][]byte{
		"SymbolicID":                  {0x01},
		"SymbolicID truncated":        {0x01, 0x00, 0x00},
		"NamespaceURI":                {0x02},
		"LocalizedText":               {0x04, 0x00},
		"Locale":                      {0x08, 0x00, 0x00, 0x00},
		"AdditionalInfo":              {0x10},
		"AdditionalInfo truncated":    {0x10, 0x05, 0x00, 0x00, 0x00, 0x62},
		"AdditionalInfo huge":         cat([]byte{0x10}, le32(0x7FFFFFFF), []byte{0x62}),
		"AdditionalInfo negative":     cat([]byte{0x10}, le32(-5)),
		"InnerStatusCode":             {0x20, 0x00},
		"InnerDiagnosticInfo":         {0x40},
		"InnerDiagnosticInfo partial": {0x40, 0x01, 0x00},
		"all":                         {0x7f, 0x01, 0x00, 0x00, 0x00},
		"empty":                       {},
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			expectRejected(t, input, func(dec *ua.BinaryDecoder) error {
				var v ua.DiagnosticInfo
				return dec.ReadDiagnosticInfo(&v)
			})
			// DiagnosticInfo is also a Variant type
			expectRejected(t, cat([]byte{0x19}, input), func(dec *ua.BinaryDecoder) error {
				var v ua.Variant
				return dec.ReadVariant(&v)
			})
			expectRejected(t, cat([]byte{0x99}, le32(1), input), func(dec *ua.BinaryDecoder) error {
				var v ua.Variant
				return dec.ReadVariant(&v)
			})
		})
	}
}

func TestDiagnosticInfoIssuePayload(t *testing.T) {
	// the five-byte payload from the issue report previously caused a nil pointer dereference.
	for _, input := range [][]byte{
		{0x01, 0x00, 0x00, 0x00, 0x00},
		{0x19, 0x01, 0x00, 0x00, 0x00, 0x00},
	} {
		dec := ua.NewBinaryDecoder(bytes.NewReader(input), ua.NewEncodingContext())
		if input[0] == 0x19 {
			var v ua.Variant
			if err := dec.ReadVariant(&v); err != nil {
				t.Fatal(err)
			}
			assert.DeepEqual(t, v, ua.Variant(ua.DiagnosticInfo{SymbolicID: int32Ptr(0)}))
			continue
		}
		var v ua.DiagnosticInfo
		if err := dec.ReadDiagnosticInfo(&v); err != nil {
			t.Fatal(err)
		}
		assert.DeepEqual(t, v, ua.DiagnosticInfo{SymbolicID: int32Ptr(0)})
	}
}

func TestDiagnosticInfoNestingLimit(t *testing.T) {
	// DiagnosticInfo containing an InnerDiagnosticInfo containing...
	input := cat(bytes.Repeat([]byte{0x40}, 10_000), []byte{0x00})
	read := func(dec *ua.BinaryDecoder) error {
		var v ua.DiagnosticInfo
		return dec.ReadDiagnosticInfo(&v)
	}
	expectRejected(t, input, read)
	dec := ua.NewBinaryDecoder(bytes.NewReader(input), ua.NewEncodingContext())
	if err := read(dec); !errors.Is(err, ua.BadEncodingLimitsExceeded) {
		t.Fatalf("expected BadEncodingLimitsExceeded, got %v", err)
	}

	// nesting within the limit decodes.
	want := ua.DiagnosticInfo{SymbolicID: int32Ptr(1)}
	for i := 0; i < 50; i++ {
		inner := want
		want = ua.DiagnosticInfo{InnerDiagnosticInfo: &inner}
	}
	buf := &bytes.Buffer{}
	if err := ua.NewBinaryEncoder(buf, ua.NewEncodingContext()).WriteDiagnosticInfo(want); err != nil {
		t.Fatal(err)
	}
	dec = ua.NewBinaryDecoder(buf, ua.NewEncodingContext())
	var got ua.DiagnosticInfo
	if err := dec.ReadDiagnosticInfo(&got); err != nil {
		t.Fatal(err)
	}
	assert.DeepEqual(t, got, want)
}

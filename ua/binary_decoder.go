// Copyright 2021 Converter Systems LLC. All rights reserved.

package ua

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"reflect"
	"sync"
	"time"
	"unsafe"

	"github.com/google/uuid"
)

var (
	typeToDecoderMap sync.Map
)

const (
	// maxNestingDepth limits how deeply Variants, DataValues, ExtensionObjects and
	// DiagnosticInfos may be nested within one another, so that a crafted message
	// cannot exhaust the stack. Each of these values counts as one level. Other
	// OPC UA stacks use similar limits, e.g. open62541 allows 100 levels.
	maxNestingDepth = 100

	// maxPreallocBytes limits the memory allocated for a String, ByteString or array
	// before its contents have been read, when the number of unread bytes of the
	// input is unknown. Beyond this, memory is allocated as the contents are decoded,
	// so that the memory used stays proportional to the size of the input.
	maxPreallocBytes = 64 * 1024

	// maxPreallocRatio limits the memory allocated for arrays before their elements
	// have been decoded to this many bytes per unread byte of the input, if that is
	// more than maxPreallocBytes. This limit applies to all the arrays being decoded,
	// which may be nested. Decoded elements may be much larger than their encoding
	// (a DataValue may be encoded in one byte), so this bounds the memory allocated
	// for arrays that then fail to decode. Beyond this, memory is allocated as
	// elements are decoded.
	maxPreallocRatio = 4

	// minChunkBytes is the least that a String or ByteString of unknown length is read
	// in at a time, ahead of allocating memory for it if need be, so that the chunks
	// it is read in are few, even if little memory may be allocated.
	minChunkBytes = 4096

	// maxEmptyArraySlices limits the number of slices at each level of a
	// multi-dimensional array with no elements, e.g. one of ArrayDimensions [n, 0],
	// so that the memory such an array uses stays proportional to its encoding.
	maxEmptyArraySlices = 16
)

// intLener is implemented by inputs that report the number of unread bytes, such as
// *bytes.Reader and *bytes.Buffer.
type intLener interface {
	Len() int
}

// int64Lener is implemented by inputs that report the number of unread bytes, such as
// the buffers of github.com/djherbis/buffer.
type int64Lener interface {
	Len() int64
}

// BinaryDecoder decodes the UA binary protocol.
type BinaryDecoder struct {
	r  io.Reader
	ec EncodingContext
	bs [8]byte

	// lenr reports the number of unread bytes of r, if r has a Len() int method.
	lenr intLener
	// len64r reports the number of unread bytes of r, if r has a Len() int64 method.
	// As this may be costly, its result is sampled, and the bytes read since are
	// subtracted from the sample.
	len64r int64Lener
	// read is the number of bytes read from r.
	read int64
	// sampledLen is the result of the last call of len64r.Len().
	sampledLen int64
	// sampledAt is the value of read when sampledLen was sampled, or -1.
	sampledAt int64
	// limit is the value of read at the end of the ExtensionObject body being
	// decoded, or math.MaxInt64. While a body is decoded, r is limited to it.
	limit int64
	// reserved is the memory allocated for the arrays being decoded before their
	// elements were decoded.
	reserved int64

	// limits limit the memory of the decoded values.
	limits DecodingLimits
	// used is the memory of the decoded values.
	used int64
	// allowed is the memory the decoded values may take, as last computed.
	allowed int64
	// limitExceeded reports whether a limit was exceeded while decoding the
	// outermost value.
	limitExceeded bool

	// depth is the current nesting depth of Variants, DataValues, ExtensionObjects
	// and DiagnosticInfos.
	depth int

	// scratch holds bytes read ahead of allocating memory for them.
	scratch []byte
}

// NewBinaryDecoder returns a new decoder that reads from an io.Reader.
//
// If r reports the number of unread bytes with a Len method, as *bytes.Reader,
// *bytes.Buffer and the buffers of github.com/djherbis/buffer do, then Strings,
// ByteStrings and arrays whose encoded length exceeds the unread bytes are rejected
// before memory is allocated for them. Otherwise, memory for long Strings,
// ByteStrings and arrays is allocated as their contents are read.
//
// The memory of the decoded values is limited by DefaultDecodingLimits, or by the
// limits of ec, if it implements DecodingLimitsProvider.
func NewBinaryDecoder(r io.Reader, ec EncodingContext) *BinaryDecoder {
	dec := &BinaryDecoder{r: r, ec: ec, sampledAt: -1, limit: math.MaxInt64, limits: DefaultDecodingLimits}
	switch l := r.(type) {
	case intLener:
		dec.lenr = l
	case int64Lener:
		dec.len64r = l
	}
	if p, ok := ec.(DecodingLimitsProvider); ok {
		dec.limits = p.DecodingLimits()
	}
	return dec
}

// readFull reads exactly len(p) bytes. Callers return BadDecodingError for any error.
func (dec *BinaryDecoder) readFull(p []byte) error {
	// io.ReadAtLeast rather than io.ReadFull, so that this function can be inlined.
	n, err := io.ReadAtLeast(dec.r, p, len(p))
	dec.read += int64(n)
	return err
}

// skip reads and discards n bytes.
func (dec *BinaryDecoder) skip(n int64) error {
	if n <= 0 {
		return nil
	}
	m, err := io.CopyN(io.Discard, dec.r, n)
	dec.read += m
	if err != nil {
		return BadDecodingError
	}
	return nil
}

// remaining returns the number of unread bytes of the input, or -1 if unknown.
func (dec *BinaryDecoder) remaining() int64 {
	if dec.lenr != nil {
		return int64(dec.lenr.Len())
	}
	if dec.len64r != nil {
		if dec.sampledAt < 0 {
			dec.sampleLen()
		}
		if n := dec.sampledLen - (dec.read - dec.sampledAt); n > 0 {
			return n
		}
		return 0
	}
	return -1
}

// sampleLen samples the number of unread bytes of an input with a Len() int64 method.
func (dec *BinaryDecoder) sampleLen() {
	dec.sampledLen = dec.len64r.Len()
	dec.sampledAt = dec.read
}

// checkAvailable returns BadDecodingError if fewer than n bytes of the input remain
// unread, or if n bytes would extend beyond the ExtensionObject body being decoded.
// Otherwise it returns the number of unread bytes that may be decoded, or -1 if
// the number of unread bytes of the input is unknown.
func (dec *BinaryDecoder) checkAvailable(n int64) (int64, error) {
	if n > dec.limit-dec.read {
		return 0, BadDecodingError
	}
	rem := dec.remaining()
	if rem < 0 {
		return -1, nil
	}
	if n > rem && dec.len64r != nil {
		// the input may have grown since its length was sampled, so sample it again.
		// As a failed check ends decoding, this is not repeated for one message.
		dec.sampleLen()
		rem = dec.sampledLen
	}
	if n > rem {
		return 0, BadDecodingError
	}
	return min(rem, dec.limit-dec.read), nil
}

// readLength reads the Int32 length of a String, ByteString or array. It returns -1
// if the value is null, and BadDecodingError if the length is otherwise negative.
func (dec *BinaryDecoder) readLength() (int, error) {
	var n int32
	if err := dec.ReadInt32(&n); err != nil {
		return 0, BadDecodingError
	}
	if n < -1 {
		return 0, BadDecodingError
	}
	return int(n), nil
}

// readBytes reads n bytes, where n is a length read from the input.
func (dec *BinaryDecoder) readBytes(n int) ([]byte, error) {
	rem, err := dec.checkAvailable(int64(n))
	if err != nil {
		return nil, err
	}
	if rem >= 0 || n == 0 {
		if err := dec.allocate(int64(n)); err != nil {
			return nil, err
		}
		bs := make([]byte, n)
		if err := dec.readFull(bs); err != nil {
			return nil, BadDecodingError
		}
		return bs, nil
	}
	// the number of unread bytes is unknown, so read the bytes in chunks.
	var chunks [][]byte
	for total := 0; total < n; {
		var chunk []byte
		if k := dec.chunkLen(total, n, 1, 0); k >= min(minChunkBytes, n-total) {
			if err := dec.allocate(int64(k)); err != nil {
				return nil, err
			}
			chunk = make([]byte, k)
			if err := dec.readFull(chunk); err != nil {
				return nil, BadDecodingError
			}
		} else {
			// little memory may be allocated now, so read ahead, which allows more.
			if dec.scratch == nil {
				dec.scratch = make([]byte, minChunkBytes)
			}
			k = min(minChunkBytes, n-total)
			if err := dec.readFull(dec.scratch[:k]); err != nil {
				return nil, BadDecodingError
			}
			if err := dec.allocate(int64(k)); err != nil {
				return nil, err
			}
			chunk = make([]byte, k)
			copy(chunk, dec.scratch)
		}
		chunks = append(chunks, chunk)
		total += len(chunk)
	}
	return joinChunks(chunks, n), nil
}

// chunkLen returns the number of elements of size bytes to allocate next for a
// value of n elements, of which total have been decoded, from an input of unknown
// length, where overhead is the memory that the chunk takes besides its elements.
// The memory the value will take cannot be known in advance, so its elements are
// decoded in chunks of at most maxPreallocBytes at first, then of at most as many
// elements as have been decoded, so that the memory stays proportional to the input
// decoded, and of no more than the memory that may be allocated now, which grows
// with the input.
func (dec *BinaryDecoder) chunkLen(total, n int, size, overhead int64) int {
	k := int64(min(max(total, int(maxPreallocBytes/size), 1), n-total))
	return int(min(k, max(1, (dec.allowedMemory()-dec.used-overhead)/size)))
}

// chunkOverhead returns the memory that the chunk after the given number of chunks
// takes besides its elements: none for the first chunk, and the slice that holds
// it in the list of chunks for each later chunk.
func chunkOverhead(chunks int) int64 {
	if chunks == 0 {
		return 0
	}
	return sliceHeaderSize
}

// joinChunks returns the n elements of the chunks in one slice. Until the chunks
// are released, this takes twice the memory accounted for them.
func joinChunks[T any](chunks [][]T, n int) []T {
	if len(chunks) == 1 {
		return chunks[0]
	}
	s := make([]T, 0, n)
	for _, chunk := range chunks {
		s = append(s, chunk...)
	}
	return s
}

// reserve returns the capacity to allocate for an array of n elements of elemSize
// bytes before they are decoded, where rem is the number of unread bytes of the
// input. It also returns the memory reserved for the array, which the caller must
// release once the array has been decoded, or has failed to decode.
func (dec *BinaryDecoder) reserve(n int, elemSize uintptr, rem int64) (int, int64) {
	if elemSize == 0 {
		return n, 0
	}
	limit := max(maxPreallocBytes, min(rem, math.MaxInt64/maxPreallocRatio)*maxPreallocRatio)
	// arrays that contain this one have already reserved memory.
	c := min(int64(n), max(1, (limit-dec.reserved)/int64(elemSize)))
	r := c * int64(elemSize)
	dec.reserved += r
	return int(c), r
}

// allocate accounts for n bytes of memory that are about to be allocated for decoded
// values. It returns BadEncodingLimitsExceeded if the values would take more memory
// than the decoding limits allow.
func (dec *BinaryDecoder) allocate(n int64) error {
	dec.used += n
	if dec.used <= dec.allowed {
		return nil
	}
	return dec.checkMemory()
}

// checkMemory computes the memory the decoded values may take, which grows with the
// input, and returns BadEncodingLimitsExceeded if they take more.
func (dec *BinaryDecoder) checkMemory() error {
	if dec.len64r != nil {
		// the input may have grown since its length was sampled.
		dec.sampleLen()
	}
	dec.allowed = dec.allowedMemory()
	if dec.used > dec.allowed {
		dec.limitExceeded = true
		return BadEncodingLimitsExceeded
	}
	return nil
}

// allowedMemory returns the memory the decoded values may take, which grows with the
// input.
func (dec *BinaryDecoder) allowedMemory() int64 {
	l := dec.limits
	allowed := int64(math.MaxInt64)
	if l.MemoryPerInputByte > 0 {
		input := dec.read
		if rem := dec.remaining(); rem > 0 {
			input += min(rem, math.MaxInt64-input)
		}
		base := max(l.MinMemory, 0)
		if input <= (math.MaxInt64-base)/l.MemoryPerInputByte {
			allowed = base + l.MemoryPerInputByte*input
		}
	}
	if l.MaxMemory > 0 {
		allowed = min(allowed, l.MaxMemory)
	}
	return allowed
}

// limitError returns the error with which decoding a value failed, or
// BadEncodingLimitsExceeded if it failed because a decoding limit was exceeded and
// the value is not contained in another.
func (dec *BinaryDecoder) limitError(err error) error {
	if dec.depth != 0 {
		return err
	}
	exceeded := dec.limitExceeded
	dec.limitExceeded = false
	if err != nil && exceeded {
		return BadEncodingLimitsExceeded
	}
	return err
}

// readArray reads an array of elements that are each encoded in at least minSize bytes.
func readArray[T any](dec *BinaryDecoder, minSize int64, read func(*BinaryDecoder, *T) error) ([]T, error) {
	n, err := dec.readLength()
	if err != nil {
		return nil, err
	}
	if n < 0 {
		return nil, nil
	}
	rem, err := dec.checkAvailable(int64(n) * minSize)
	if err != nil {
		return nil, dec.limitError(err)
	}
	if rem < 0 {
		values, err := readArrayChunks(dec, n, read)
		return values, dec.limitError(err)
	}
	// the length of the array fits the input, so account for the memory the array
	// takes once decoded, so that one that is too large is rejected before memory is
	// allocated for it.
	var zero T
	size := int64(unsafe.Sizeof(zero))
	if err := dec.allocate(int64(n) * size); err != nil {
		return nil, dec.limitError(err)
	}
	c, reserved := dec.reserve(n, uintptr(size), rem)
	values := make([]T, 0, c)
	for i := 0; i < n; i++ {
		if i == cap(values) {
			// grow the array as its elements are decoded.
			values = growExact(values, min(i, n-i))
		}
		values = values[:i+1]
		if err = read(dec, &values[i]); err != nil {
			break
		}
	}
	dec.reserved -= reserved
	if err != nil {
		return nil, dec.limitError(err)
	}
	return values, nil
}

// readArrayChunks reads the n elements of an array from an input of unknown length,
// in chunks.
func readArrayChunks[T any](dec *BinaryDecoder, n int, read func(*BinaryDecoder, *T) error) ([]T, error) {
	var zero T
	size := int64(unsafe.Sizeof(zero))
	chunks := [][]T{}
	for total := 0; total < n; {
		overhead := chunkOverhead(len(chunks))
		k := dec.chunkLen(total, n, size, overhead)
		if err := dec.allocate(int64(k)*size + overhead); err != nil {
			return nil, err
		}
		chunk := make([]T, k)
		for i := range chunk {
			if err := read(dec, &chunk[i]); err != nil {
				return nil, err
			}
		}
		chunks = append(chunks, chunk)
		total += k
	}
	if n == 0 {
		return []T{}, nil
	}
	return joinChunks(chunks, n), nil
}

// growExact returns s with a capacity of exactly len(s)+k.
func growExact[T any](s []T, k int) []T {
	t := make([]T, len(s), len(s)+k)
	copy(t, s)
	return t
}

// enter increments the nesting depth before decoding a value that may contain other
// values. It returns BadEncodingLimitsExceeded if the depth would exceed the limit.
func (dec *BinaryDecoder) enter() error {
	if dec.depth >= maxNestingDepth {
		dec.limitExceeded = true
		return BadEncodingLimitsExceeded
	}
	dec.depth++
	return nil
}

// leave decrements the nesting depth after decoding a value that may contain other values.
func (dec *BinaryDecoder) leave() {
	dec.depth--
}

// minEncodedSize returns the minimum number of bytes in the encoding of a value of the type.
func minEncodedSize(typ reflect.Type) int64 {
	switch typ {
	case typeDateTime:
		return 8
	case typeGUID:
		return 16
	case typeNodeID, typeExpandedNodeID:
		return 2
	case typeQualifiedName:
		return 6
	case typeLocalizedText, typeDataValue, typeDiagnosticInfo, typeVariant:
		return 1
	case typeExtensionObject:
		return 3
	}
	switch typ.Kind() {
	case reflect.Bool, reflect.Int8, reflect.Uint8:
		return 1
	case reflect.Int16, reflect.Uint16:
		return 2
	case reflect.Int32, reflect.Uint32, reflect.Float32, reflect.String, reflect.Slice:
		return 4
	case reflect.Int64, reflect.Uint64, reflect.Float64:
		return 8
	case reflect.Ptr:
		return minEncodedSize(typ.Elem())
	case reflect.Struct:
		var n int64
		for i := 0; i < typ.NumField(); i++ {
			n += minEncodedSize(typ.Field(i).Type)
		}
		return n
	}
	return 0
}

type decoderFunc func(*BinaryDecoder, unsafe.Pointer) error

// Decode decodes the value using the UA Binary protocol.
func (dec *BinaryDecoder) Decode(v any) error {
	typ := reflect.TypeOf(v)
	if typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}
	ptr := ((*interfaceHeader)(unsafe.Pointer(&v))).ptr

	// try to retrieve decoder from cache.
	if f, ok := typeToDecoderMap.Load(typ); ok {

		// if found, call it.
		if err := f.(decoderFunc)(dec, ptr); err != nil {
			return dec.limitError(err)
		}
		return nil
	}

	f, err := getDecoder(typ)
	if err != nil {
		return err
	}
	typeToDecoderMap.Store(typ, f)

	// call the decoder
	if err := f(dec, ptr); err != nil {
		return dec.limitError(err)
	}
	return nil
}

func getDecoder(typ reflect.Type) (decoderFunc, error) {
	switch typ.Kind() {
	case reflect.Struct:
		switch typ {
		case typeDateTime:
			return getDateTimeDecoder()
		case typeGUID:
			return getGUIDDecoder()
		case typeExpandedNodeID:
			return getExpandedNodeIDDecoder()
		case typeQualifiedName:
			return getQualifiedNameDecoder()
		case typeLocalizedText:
			return getLocalizedTextDecoder()
		case typeDataValue:
			return getDataValueDecoder()
		case typeDiagnosticInfo:
			return getDiagnosticInfoDecoder()
		default:
			return getStructDecoder(typ)
		}
	case reflect.Slice:
		elemTyp := typ.Elem()
		switch elemTyp.Kind() {
		case reflect.Uint8:
			return getByteArrayDecoder()
		default:
			return getSliceDecoder(typ)
		}
	case reflect.Ptr:
		typ = typ.Elem()
		return getStructPtrDecoder(typ)
	case reflect.Interface:
		switch typ {
		case typeNodeID:
			return getNodeIDDecoder()
		case typeExtensionObject:
			return getExtensionObjectDecoder()
		case typeVariant:
			return getVariantDecoder()
		}
	case reflect.Bool:
		return getBooleanDecoder()
	case reflect.Int8:
		return getSByteDecoder()
	case reflect.Uint8:
		return getByteDecoder()
	case reflect.Int16:
		return getInt16Decoder()
	case reflect.Uint16:
		return getUInt16Decoder()
	case reflect.Int32:
		return getInt32Decoder()
	case reflect.Uint32:
		return getUInt32Decoder()
	case reflect.Int64:
		return getInt64Decoder()
	case reflect.Uint64:
		return getUInt64Decoder()
	case reflect.Float32:
		return getFloatDecoder()
	case reflect.Float64:
		return getDoubleDecoder()
	case reflect.String:
		return getStringDecoder()
	}
	return nil, fmt.Errorf("unsupported type: %s", typ)
}

func getStructDecoder(typ reflect.Type) (decoderFunc, error) {
	decoders := []decoderFunc{}
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		dec, err := getDecoder(field.Type)
		if err != nil {
			return nil, err
		}
		offset := field.Offset
		decoders = append(decoders, func(buf *BinaryDecoder, p unsafe.Pointer) error {
			return dec(buf, unsafe.Pointer(uintptr(p)+offset))
		})
	}
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		for _, dec := range decoders {
			if err := dec(buf, p); err != nil {
				return err
			}
		}
		return nil
	}, nil
}
func getStructPtrDecoder(typ reflect.Type) (decoderFunc, error) {
	decoders := []decoderFunc{}
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		dec, err := getDecoder(field.Type)
		if err != nil {
			return nil, err
		}
		offset := field.Offset
		decoders = append(decoders, func(buf *BinaryDecoder, p unsafe.Pointer) error {
			return dec(buf, unsafe.Pointer(uintptr(p)+offset))
		})
	}
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		p2 := unsafe.Pointer(*(**struct{})(p))
		if p2 == nilPtr {
			if err := buf.allocate(int64(typ.Size())); err != nil {
				return err
			}
			v := reflect.New(typ)
			reflect.NewAt(v.Type(), p).Elem().Set(v)
			p2 = unsafe.Pointer(*(**struct{})(p))
		}
		for _, dec := range decoders {
			if err := dec(buf, p2); err != nil {
				return err
			}
		}
		return nil
	}, nil
}

func getSliceDecoder(typ reflect.Type) (decoderFunc, error) {
	elem := typ.Elem()
	elemSize := elem.Size()
	elemDecoder, err := getDecoder(elem)
	if err != nil {
		return nil, err
	}
	minSize := minEncodedSize(elem)
	if minSize == 0 && elemSize != 0 {
		// decoding the elements would neither read input nor be free.
		return nil, fmt.Errorf("unsupported type: %s", typ)
	}
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		n, err := buf.readLength()
		if err != nil {
			return err
		}
		if n <= 0 {
			reflect.NewAt(typ, p).Elem().Set(reflect.MakeSlice(typ, 0, 0))
			return nil
		}
		if minSize == 0 {
			// elements such as empty structures have no encoding, nor any content.
			reflect.NewAt(typ, p).Elem().Set(reflect.MakeSlice(typ, n, n))
			return nil
		}
		rem, err := buf.checkAvailable(int64(n) * minSize)
		if err != nil {
			return err
		}
		if rem < 0 {
			// the number of unread bytes is unknown, so decode the elements in chunks.
			var chunks []reflect.Value
			for total := 0; total < n; {
				overhead := chunkOverhead(len(chunks))
				k := buf.chunkLen(total, n, int64(elemSize), overhead)
				if err := buf.allocate(int64(k)*int64(elemSize) + overhead); err != nil {
					return err
				}
				chunk := reflect.MakeSlice(typ, k, k)
				for i := 0; i < k; i++ {
					if err := elemDecoder(buf, unsafe.Add(chunk.UnsafePointer(), uintptr(i)*elemSize)); err != nil {
						return err
					}
				}
				chunks = append(chunks, chunk)
				total += k
			}
			s := chunks[0]
			if len(chunks) > 1 {
				s = reflect.MakeSlice(typ, n, n)
				off := 0
				for _, chunk := range chunks {
					off += reflect.Copy(s.Slice(off, n), chunk)
				}
			}
			reflect.NewAt(typ, p).Elem().Set(s)
			return nil
		}
		// the length of the array fits the input, so account for the memory the array
		// takes once decoded, so that one that is too large is rejected before memory
		// is allocated for it.
		if err := buf.allocate(int64(n) * int64(elemSize)); err != nil {
			return err
		}
		c, reserved := buf.reserve(n, elemSize, rem)
		s := reflect.MakeSlice(typ, c, c)
		for i := 0; i < n; i++ {
			if i == c {
				// grow the slice as elements are decoded.
				c += min(c, n-c)
				s2 := reflect.MakeSlice(typ, c, c)
				reflect.Copy(s2, s)
				s = s2
			}
			if err = elemDecoder(buf, unsafe.Add(s.UnsafePointer(), uintptr(i)*elemSize)); err != nil {
				break
			}
		}
		buf.reserved -= reserved
		if err != nil {
			return err
		}
		reflect.NewAt(typ, p).Elem().Set(s)
		return nil
	}, nil
}
func getBooleanDecoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadBoolean((*bool)(p))
	}, nil
}
func getSByteDecoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadSByte((*int8)(p))
	}, nil
}
func getByteDecoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadByte((*uint8)(p))
	}, nil
}
func getInt16Decoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadInt16((*int16)(p))
	}, nil
}
func getUInt16Decoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadUInt16((*uint16)(p))
	}, nil
}
func getInt32Decoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadInt32((*int32)(p))
	}, nil
}
func getUInt32Decoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadUInt32((*uint32)(p))
	}, nil
}
func getInt64Decoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadInt64((*int64)(p))
	}, nil
}
func getUInt64Decoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadUInt64((*uint64)(p))
	}, nil
}
func getFloatDecoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadFloat((*float32)(p))
	}, nil
}
func getDoubleDecoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadDouble((*float64)(p))
	}, nil
}
func getStringDecoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadString((*string)(p))
	}, nil
}
func getNodeIDDecoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadNodeID((*NodeID)(p))
	}, nil
}
func getExpandedNodeIDDecoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadExpandedNodeID((*ExpandedNodeID)(p))
	}, nil
}
func getDateTimeDecoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadDateTime((*time.Time)(p))
	}, nil
}
func getGUIDDecoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadGUID((*uuid.UUID)(p))
	}, nil
}
func getQualifiedNameDecoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadQualifiedName((*QualifiedName)(p))
	}, nil
}
func getLocalizedTextDecoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadLocalizedText((*LocalizedText)(p))
	}, nil
}
func getExtensionObjectDecoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadExtensionObject((*ExtensionObject)(p))
	}, nil
}
func getVariantDecoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadVariant((*Variant)(p))
	}, nil
}
func getDataValueDecoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadDataValue((*DataValue)(p))
	}, nil
}
func getDiagnosticInfoDecoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadDiagnosticInfo((*DiagnosticInfo)(p))
	}, nil
}
func getByteArrayDecoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadByteArray((*[]uint8)(p))
	}, nil
}

// ReadBoolean reads a bool.
func (dec *BinaryDecoder) ReadBoolean(value *bool) error {
	if err := dec.readFull(dec.bs[:1]); err != nil {
		return BadDecodingError
	}
	*value = dec.bs[0] != 0
	return nil
}

// ReadSByte reads a int8.
func (dec *BinaryDecoder) ReadSByte(value *int8) error {
	if err := dec.readFull(dec.bs[:1]); err != nil {
		return BadDecodingError
	}
	*value = int8(dec.bs[0])
	return nil
}

// ReadByte reads a byte.
func (dec *BinaryDecoder) ReadByte(value *byte) error {
	if err := dec.readFull(dec.bs[:1]); err != nil {
		return BadDecodingError
	}
	*value = dec.bs[0]
	return nil
}

// ReadInt16 reads a int16.
func (dec *BinaryDecoder) ReadInt16(value *int16) error {
	if err := dec.readFull(dec.bs[:2]); err != nil {
		return BadDecodingError
	}
	*value = int16(binary.LittleEndian.Uint16(dec.bs[:2]))
	return nil
}

// ReadUInt16 reads a uint16.
func (dec *BinaryDecoder) ReadUInt16(value *uint16) error {
	if err := dec.readFull(dec.bs[:2]); err != nil {
		return BadDecodingError
	}
	*value = binary.LittleEndian.Uint16(dec.bs[:2])
	return nil
}

// ReadInt32 reads a int32.
func (dec *BinaryDecoder) ReadInt32(value *int32) error {
	if err := dec.readFull(dec.bs[:4]); err != nil {
		return BadDecodingError
	}
	*value = int32(binary.LittleEndian.Uint32(dec.bs[:4]))
	return nil
}

// ReadUInt32 reads a uint32.
func (dec *BinaryDecoder) ReadUInt32(value *uint32) error {
	if err := dec.readFull(dec.bs[:4]); err != nil {
		return BadDecodingError
	}
	*value = binary.LittleEndian.Uint32(dec.bs[:4])
	return nil
}

// ReadInt64 reads a int64.
func (dec *BinaryDecoder) ReadInt64(value *int64) error {
	if err := dec.readFull(dec.bs[:8]); err != nil {
		return BadDecodingError
	}
	*value = int64(binary.LittleEndian.Uint64(dec.bs[:8]))
	return nil
}

// ReadUInt64 reads a int64.
func (dec *BinaryDecoder) ReadUInt64(value *uint64) error {
	if err := dec.readFull(dec.bs[:8]); err != nil {
		return BadDecodingError
	}
	*value = binary.LittleEndian.Uint64(dec.bs[:8])
	return nil
}

// ReadFloat reads a float32.
func (dec *BinaryDecoder) ReadFloat(value *float32) error {
	if err := dec.readFull(dec.bs[:4]); err != nil {
		return BadDecodingError
	}
	*value = math.Float32frombits(binary.LittleEndian.Uint32(dec.bs[:4]))
	return nil
}

// ReadDouble reads a float64.
func (dec *BinaryDecoder) ReadDouble(value *float64) error {
	if err := dec.readFull(dec.bs[:8]); err != nil {
		return BadDecodingError
	}
	*value = math.Float64frombits(binary.LittleEndian.Uint64(dec.bs[:8]))
	return nil
}

// ReadString reads a string.
func (dec *BinaryDecoder) ReadString(value *string) error {
	n, err := dec.readLength()
	if err != nil {
		return BadDecodingError
	}
	if n < 0 {
		*value = ""
		return nil
	}
	bs, err := dec.readBytes(n)
	if err != nil {
		return err
	}
	// eliminate alloc of a second byte array and copying from one byte array to another.
	*value = *(*string)(unsafe.Pointer(&bs))
	return nil
}

// ReadDateTime reads a time.Time.
func (dec *BinaryDecoder) ReadDateTime(value *time.Time) error {
	// ticks are 100 nanosecond intervals since January 1, 1601
	var ticks int64
	if err := dec.ReadInt64(&ticks); err != nil {
		return BadDecodingError
	}
	if ticks < 0 {
		ticks = 0
	}
	if ticks == 0x7FFFFFFFFFFFFFFF {
		ticks = 2650467743990000000
	}
	*value = time.Unix(ticks/10000000-11644473600, (ticks%10000000)*100).UTC()
	return nil
}

// ReadGUID reads a uuid.UUID.
func (dec *BinaryDecoder) ReadGUID(value *uuid.UUID) error {
	if err := dec.readFull(dec.bs[:8]); err != nil {
		return BadDecodingError
	}
	v := uuid.UUID{}
	v[0] = dec.bs[3]
	v[1] = dec.bs[2]
	v[2] = dec.bs[1]
	v[3] = dec.bs[0]
	v[4] = dec.bs[5]
	v[5] = dec.bs[4]
	v[6] = dec.bs[7]
	v[7] = dec.bs[6]
	if err := dec.readFull(v[8:]); err != nil {
		return BadDecodingError
	}
	*value = v
	return nil
}

// ReadByteString reads a ByteString.
func (dec *BinaryDecoder) ReadByteString(value *ByteString) error {
	n, err := dec.readLength()
	if err != nil {
		return BadDecodingError
	}
	if n <= 0 {
		*value = ""
		return nil
	}
	bs, err := dec.readBytes(n)
	if err != nil {
		return err
	}
	*value = *(*ByteString)(unsafe.Pointer(&bs))
	return nil
}

// ReadXMLElement reads a XMLElement.
func (dec *BinaryDecoder) ReadXMLElement(value *XMLElement) error {
	var s string
	if err := dec.ReadString(&s); err != nil {
		return err
	}
	*value = XMLElement(s)
	return nil
}

var nilGuid = uuid.UUID{}

// ReadNodeID reads a NodeID.
func (dec *BinaryDecoder) ReadNodeID(value *NodeID) error {
	var b byte
	if err := dec.ReadByte(&b); err != nil {
		return BadDecodingError
	}
	switch b {
	case 0x00:
		var id byte
		if err := dec.ReadByte(&id); err != nil {
			return BadDecodingError
		}
		if id == 0 {
			*value = nil
			return nil
		}
		*value = NewNodeIDNumeric(uint16(0), uint32(id))
		return dec.allocate(nodeIDNumericSize)

	case 0x01:
		var ns byte
		var id uint16
		if err := dec.ReadByte(&ns); err != nil {
			return BadDecodingError
		}
		if err := dec.ReadUInt16(&id); err != nil {
			return BadDecodingError
		}
		*value = NewNodeIDNumeric(uint16(ns), uint32(id))
		return dec.allocate(nodeIDNumericSize)

	case 0x02:
		var ns uint16
		var id uint32
		if err := dec.ReadUInt16(&ns); err != nil {
			return BadDecodingError
		}
		if err := dec.ReadUInt32(&id); err != nil {
			return BadDecodingError
		}
		*value = NewNodeIDNumeric(ns, uint32(id))
		return dec.allocate(nodeIDNumericSize)

	case 0x03:
		var ns uint16
		var id string
		if err := dec.ReadUInt16(&ns); err != nil {
			return BadDecodingError
		}
		if err := dec.ReadString(&id); err != nil {
			return err
		}
		if ns == 0 && id == "" {
			*value = nil
			return nil
		}
		*value = NewNodeIDString(ns, id)
		return dec.allocate(nodeIDStringSize)

	case 0x04:
		var ns uint16
		var id uuid.UUID
		if err := dec.ReadUInt16(&ns); err != nil {
			return BadDecodingError
		}
		if err := dec.ReadGUID(&id); err != nil {
			return BadDecodingError
		}
		if ns == 0 && id == nilGuid {
			*value = nil
			return nil
		}
		*value = NewNodeIDGUID(ns, id)
		return dec.allocate(nodeIDGUIDSize)

	case 0x05:
		var ns uint16
		var id ByteString
		if err := dec.ReadUInt16(&ns); err != nil {
			return BadDecodingError
		}
		if err := dec.ReadByteString(&id); err != nil {
			return err
		}
		if ns == 0 && id == "" {
			*value = nil
			return nil
		}
		*value = NewNodeIDOpaque(ns, id)
		return dec.allocate(nodeIDOpaqueSize)

	default:
		return BadDecodingError
	}
}

func (dec *BinaryDecoder) ReadExpandedNodeID(value *ExpandedNodeID) error {
	var (
		n   NodeID
		nsu string
		svr uint32
		b   byte
	)
	if err := dec.ReadByte(&b); err != nil {
		return BadDecodingError
	}
	switch b & 0x0F {
	case 0x00:
		var id byte
		if err := dec.ReadByte(&id); err != nil {
			return BadDecodingError
		}
		if id == 0 {
			n = nil
		} else {
			n = NewNodeIDNumeric(uint16(0), uint32(id))
		}
	case 0x01:
		var ns byte
		if err := dec.ReadByte(&ns); err != nil {
			return BadDecodingError
		}
		var id uint16
		if err := dec.ReadUInt16(&id); err != nil {
			return BadDecodingError
		}
		n = NewNodeIDNumeric(uint16(ns), uint32(id))

	case 0x02:
		var ns uint16
		if err := dec.ReadUInt16(&ns); err != nil {
			return BadDecodingError
		}
		var id uint32
		if err := dec.ReadUInt32(&id); err != nil {
			return BadDecodingError
		}
		n = NewNodeIDNumeric(ns, id)

	case 0x03:
		var ns uint16
		if err := dec.ReadUInt16(&ns); err != nil {
			return BadDecodingError
		}
		var id string
		if err := dec.ReadString(&id); err != nil {
			return err
		}
		n = NewNodeIDString(ns, id)

	case 0x04:
		var ns uint16
		if err := dec.ReadUInt16(&ns); err != nil {
			return BadDecodingError
		}
		var id uuid.UUID
		if err := dec.ReadGUID(&id); err != nil {
			return BadDecodingError
		}
		n = NewNodeIDGUID(ns, id)

	case 0x05:
		var ns uint16
		if err := dec.ReadUInt16(&ns); err != nil {
			return BadDecodingError
		}
		var id ByteString
		if err := dec.ReadByteString(&id); err != nil {
			return err
		}
		n = NewNodeIDOpaque(ns, id)

	default:
		return BadDecodingError
	}

	if (b & 0x80) != 0 {
		if err := dec.ReadString(&nsu); err != nil {
			return err
		}
	}

	if (b & 0x40) != 0 {
		if err := dec.ReadUInt32(&svr); err != nil {
			return BadDecodingError
		}
	}
	*value = ExpandedNodeID{svr, nsu, n}
	return dec.allocate(nodeIDSize(n))
}

// sizes of the values that NodeIDs hold.
const (
	nodeIDNumericSize = int64(unsafe.Sizeof(NodeIDNumeric{}))
	nodeIDStringSize  = int64(unsafe.Sizeof(NodeIDString{}))
	nodeIDGUIDSize    = int64(unsafe.Sizeof(NodeIDGUID{}))
	nodeIDOpaqueSize  = int64(unsafe.Sizeof(NodeIDOpaque{}))
)

// nodeIDSize returns the size of the value that a NodeID holds.
func nodeIDSize(n NodeID) int64 {
	switch n.(type) {
	case NodeIDNumeric:
		return nodeIDNumericSize
	case NodeIDString:
		return nodeIDStringSize
	case NodeIDGUID:
		return nodeIDGUIDSize
	case NodeIDOpaque:
		return nodeIDOpaqueSize
	}
	return 0
}

// ReadStatusCode reads a StatusCode.
func (dec *BinaryDecoder) ReadStatusCode(value *StatusCode) error {
	var u1 uint32
	if err := dec.ReadUInt32(&u1); err != nil {
		return BadDecodingError
	}
	*value = StatusCode(u1)
	return nil
}

// ReadQualifiedName reads a QualifiedName.
func (dec *BinaryDecoder) ReadQualifiedName(value *QualifiedName) error {
	var (
		ns   uint16
		name string
	)
	if err := dec.ReadUInt16(&ns); err != nil {
		return BadDecodingError
	}
	if err := dec.ReadString(&name); err != nil {
		return err
	}
	*value = QualifiedName{ns, name}
	return nil
}

// ReadLocalizedText reads a LocalizedText.
func (dec *BinaryDecoder) ReadLocalizedText(value *LocalizedText) error {
	var (
		text   string
		locale string
	)
	var b byte
	if err := dec.ReadByte(&b); err != nil {
		return BadDecodingError
	}
	if (b & 1) != 0 {
		if err := dec.ReadString(&locale); err != nil {
			return err
		}
	}
	if (b & 2) != 0 {
		if err := dec.ReadString(&text); err != nil {
			return err
		}
	}
	*value = LocalizedText{text, locale}
	return nil
}

// ReadExtensionObject reads an Extensionobject.
func (dec *BinaryDecoder) ReadExtensionObject(value *ExtensionObject) error {
	if err := dec.enter(); err != nil {
		return err
	}
	err := dec.readExtensionObject(value)
	dec.leave()
	return dec.limitError(err)
}

func (dec *BinaryDecoder) readExtensionObject(value *ExtensionObject) error {
	var nodeID NodeID
	if err := dec.ReadNodeID(&nodeID); err != nil {
		return BadDecodingError
	}
	var b byte
	if err := dec.ReadByte(&b); err != nil {
		return BadDecodingError
	}
	switch b {
	case 0x00:
		return nil
	case 0x01:
		id := ToExpandedNodeID(nodeID, dec.ec.NamespaceURIs())
		// lookup type
		typ, ok := FindTypeForBinaryEncodingID(id)
		if ok {
			length, err := dec.readLength()
			if err != nil {
				return BadDecodingError
			}
			if length < 0 {
				length = 0
			}
			if _, err := dec.checkAvailable(int64(length)); err != nil {
				return BadDecodingError
			}
			// the object is held on the heap.
			if err := dec.allocate(int64(typ.Size())); err != nil {
				return err
			}
			// decode the body within its length.
			outerR, outerLimit := dec.r, dec.limit
			dec.r = &io.LimitedReader{R: outerR, N: int64(length)}
			dec.limit = dec.read + int64(length)
			obj := reflect.New(typ).Elem().Interface() // TODO: decide if ptr or struct
			err = dec.Decode(obj)
			if err == nil {
				// skip the rest of the body, such as fields of a later version of the type.
				err = dec.skip(dec.limit - dec.read)
			}
			dec.r, dec.limit = outerR, outerLimit
			if err != nil {
				return BadDecodingError
			}
			*value = obj
			return nil
		}
		var body []byte
		err := dec.ReadByteArray(&body)
		if err != nil {
			return BadDecodingError
		}
		return nil
	case 0x02:
		var body XMLElement
		err := dec.ReadXMLElement(&body)
		if err != nil {
			return BadDecodingError
		}
		return nil
	default:
		return BadDecodingError
	}
}

// ReadDataValue reads a DataValue.
func (dec *BinaryDecoder) ReadDataValue(value *DataValue) error {
	if err := dec.enter(); err != nil {
		return err
	}
	err := dec.readDataValue(value)
	dec.leave()
	return dec.limitError(err)
}

func (dec *BinaryDecoder) readDataValue(value *DataValue) error {
	var (
		v                 Variant
		statusCode        StatusCode
		sourceTimestamp   time.Time
		sourcePicoseconds uint16
		serverTimestamp   time.Time
		serverPicoseconds uint16
		err               error
	)
	var b byte
	if err := dec.ReadByte(&b); err != nil {
		return BadDecodingError
	}
	if (b & 1) != 0 {
		if err := dec.ReadVariant(&v); err != nil {
			// a Variant that was read, but whose value cannot be represented.
			if err != BadDataTypeIDUnknown {
				return err
			}
			statusCode = BadDataTypeIDUnknown
		}
	}
	if (b & 2) != 0 {
		var sc StatusCode
		if err := dec.ReadStatusCode(&sc); err != nil {
			return BadDecodingError
		}
		if statusCode == 0 {
			statusCode = sc
		}
	}
	if (b & 4) != 0 {
		if err = dec.ReadDateTime(&sourceTimestamp); err != nil {
			return BadDecodingError
		}
	}
	if (b & 16) != 0 {
		if err := dec.ReadUInt16(&sourcePicoseconds); err != nil {
			return BadDecodingError
		}
	}
	if (b & 8) != 0 {
		if err = dec.ReadDateTime(&serverTimestamp); err != nil {
			return BadDecodingError
		}
	}
	if (b & 32) != 0 {
		if err := dec.ReadUInt16(&serverPicoseconds); err != nil {
			return BadDecodingError
		}
	}
	*value = DataValue{v, statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
	return nil
}

// ReadVariant reads a Variant.
func (dec *BinaryDecoder) ReadVariant(value *Variant) error {
	if err := dec.enter(); err != nil {
		return err
	}
	err := dec.readVariant(value)
	dec.leave()
	return dec.limitError(err)
}

func (dec *BinaryDecoder) readVariant(value *Variant) error {
	var b byte
	if err := dec.ReadByte(&b); err != nil {
		return BadDecodingError
	}
	// a Variant holds its value on the heap.
	size := sliceHeaderSize
	if b&VariantTypeArray == 0 {
		size = 0
		if t := int(b & 0x3F); t < len(variantValueSizes) {
			size = variantValueSizes[t]
		}
	}
	if err := dec.allocate(size); err != nil {
		return err
	}

	// If scalar value
	if (b & VariantTypeArray) == 0 {
		switch b & 0x3F {
		case VariantTypeNull:
			*value = nil
			return nil

		case VariantTypeBoolean:
			var v bool
			if err := dec.ReadBoolean(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeSByte:
			var v int8
			if err := dec.ReadSByte(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeByte:
			var v byte
			if err := dec.ReadByte(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeInt16:
			var v int16
			if err := dec.ReadInt16(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeUInt16:
			var v uint16
			if err := dec.ReadUInt16(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeInt32:
			var v int32
			if err := dec.ReadInt32(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeUInt32:
			var v uint32
			if err := dec.ReadUInt32(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeInt64:
			var v int64
			if err := dec.ReadInt64(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeUInt64:
			var v uint64
			if err := dec.ReadUInt64(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeFloat:
			var v float32
			if err := dec.ReadFloat(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeDouble:
			var v float64
			if err := dec.ReadDouble(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeString:
			var v string
			if err := dec.ReadString(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeDateTime:
			var v time.Time
			if err := dec.ReadDateTime(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeGUID:
			var v uuid.UUID
			if err := dec.ReadGUID(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeByteString:
			var v ByteString
			if err := dec.ReadByteString(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeXMLElement:
			var v XMLElement
			if err := dec.ReadXMLElement(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeNodeID:
			var v NodeID
			if err := dec.ReadNodeID(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeExpandedNodeID:
			var v ExpandedNodeID
			if err := dec.ReadExpandedNodeID(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeStatusCode:
			var v StatusCode
			if err := dec.ReadStatusCode(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeQualifiedName:
			var v QualifiedName
			if err := dec.ReadQualifiedName(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeLocalizedText:
			var v LocalizedText
			if err := dec.ReadLocalizedText(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeExtensionObject:
			var v ExtensionObject
			if err := dec.ReadExtensionObject(&v); err != nil {
				return err
			}
			*value = v
			return nil

		case VariantTypeDataValue:
			var v DataValue
			if err := dec.ReadDataValue(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeVariant:
			var v Variant
			if err := dec.ReadVariant(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeDiagnosticInfo:
			var v DiagnosticInfo
			if err := dec.ReadDiagnosticInfo(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		default:
			return BadDecodingError
		}
	}

	// if single dimension array
	if (b & VariantTypeMultiDimensionArray) == 0 {
		switch b & 0x3F {
		case VariantTypeNull:
			*value = nil
			return nil

		case VariantTypeBoolean:
			var v []bool
			if err := dec.ReadBooleanArray(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeSByte:
			var v []int8
			if err := dec.ReadSByteArray(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeByte:
			var v []byte
			if err := dec.ReadByteArray(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeInt16:
			var v []int16
			if err := dec.ReadInt16Array(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeUInt16:
			var v []uint16
			if err := dec.ReadUInt16Array(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeInt32:
			var v []int32
			if err := dec.ReadInt32Array(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeUInt32:
			var v []uint32
			if err := dec.ReadUInt32Array(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeInt64:
			var v []int64
			if err := dec.ReadInt64Array(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeUInt64:
			var v []uint64
			if err := dec.ReadUInt64Array(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeFloat:
			var v []float32
			if err := dec.ReadFloatArray(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeDouble:
			var v []float64
			if err := dec.ReadDoubleArray(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeString:
			var v []string
			if err := dec.ReadStringArray(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeDateTime:
			var v []time.Time
			if err := dec.ReadDateTimeArray(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeGUID:
			var v []uuid.UUID
			if err := dec.ReadGUIDArray(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeByteString:
			var v []ByteString
			if err := dec.ReadByteStringArray(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeXMLElement:
			var v []XMLElement
			if err := dec.ReadXMLElementArray(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeNodeID:
			var v []NodeID
			if err := dec.ReadNodeIDArray(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeExpandedNodeID:
			var v []ExpandedNodeID
			if err := dec.ReadExpandedNodeIDArray(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeStatusCode:
			var v []StatusCode
			if err := dec.ReadStatusCodeArray(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeQualifiedName:
			var v []QualifiedName
			if err := dec.ReadQualifiedNameArray(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeLocalizedText:
			var v []LocalizedText
			if err := dec.ReadLocalizedTextArray(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeExtensionObject:
			var v []ExtensionObject
			if err := dec.ReadExtensionObjectArray(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeDataValue:
			var v []DataValue
			if err := dec.ReadDataValueArray(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeVariant:
			var v []Variant
			if err := dec.ReadVariantArray(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeDiagnosticInfo:
			var v []DiagnosticInfo
			if err := dec.ReadDiagnosticInfoArray(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		default:
			return BadDecodingError
		}
	}

	// Multidimensional array
	switch b & 0x3F {
	case VariantTypeNull:
		*value = nil
		return nil
	case VariantTypeBoolean:
		return readMatrix(dec, value, (*BinaryDecoder).ReadBooleanArray)
	case VariantTypeSByte:
		return readMatrix(dec, value, (*BinaryDecoder).ReadSByteArray)
	case VariantTypeByte:
		return readMatrix(dec, value, (*BinaryDecoder).ReadByteArray)
	case VariantTypeInt16:
		return readMatrix(dec, value, (*BinaryDecoder).ReadInt16Array)
	case VariantTypeUInt16:
		return readMatrix(dec, value, (*BinaryDecoder).ReadUInt16Array)
	case VariantTypeInt32:
		return readMatrix(dec, value, (*BinaryDecoder).ReadInt32Array)
	case VariantTypeUInt32:
		return readMatrix(dec, value, (*BinaryDecoder).ReadUInt32Array)
	case VariantTypeInt64:
		return readMatrix(dec, value, (*BinaryDecoder).ReadInt64Array)
	case VariantTypeUInt64:
		return readMatrix(dec, value, (*BinaryDecoder).ReadUInt64Array)
	case VariantTypeFloat:
		return readMatrix(dec, value, (*BinaryDecoder).ReadFloatArray)
	case VariantTypeDouble:
		return readMatrix(dec, value, (*BinaryDecoder).ReadDoubleArray)
	case VariantTypeString:
		return readMatrix(dec, value, (*BinaryDecoder).ReadStringArray)
	case VariantTypeDateTime:
		return readMatrix(dec, value, (*BinaryDecoder).ReadDateTimeArray)
	case VariantTypeGUID:
		return readMatrix(dec, value, (*BinaryDecoder).ReadGUIDArray)
	case VariantTypeByteString:
		return readMatrix(dec, value, (*BinaryDecoder).ReadByteStringArray)
	case VariantTypeXMLElement:
		return readMatrix(dec, value, (*BinaryDecoder).ReadXMLElementArray)
	case VariantTypeNodeID:
		return readMatrix(dec, value, (*BinaryDecoder).ReadNodeIDArray)
	case VariantTypeExpandedNodeID:
		return readMatrix(dec, value, (*BinaryDecoder).ReadExpandedNodeIDArray)
	case VariantTypeStatusCode:
		return readMatrix(dec, value, (*BinaryDecoder).ReadStatusCodeArray)
	case VariantTypeQualifiedName:
		return readMatrix(dec, value, (*BinaryDecoder).ReadQualifiedNameArray)
	case VariantTypeLocalizedText:
		return readMatrix(dec, value, (*BinaryDecoder).ReadLocalizedTextArray)
	case VariantTypeExtensionObject:
		return readMatrix(dec, value, (*BinaryDecoder).ReadExtensionObjectArray)
	case VariantTypeDataValue:
		return readMatrix(dec, value, (*BinaryDecoder).ReadDataValueArray)
	case VariantTypeVariant:
		return readMatrix(dec, value, (*BinaryDecoder).ReadVariantArray)
	case VariantTypeDiagnosticInfo:
		return readMatrix(dec, value, (*BinaryDecoder).ReadDiagnosticInfoArray)
	default:
		return BadDecodingError
	}
}

// sliceHeaderSize is the size of a slice.
const sliceHeaderSize = int64(unsafe.Sizeof([]byte(nil)))

// variantValueSizes are the sizes of the scalar values of each type that a Variant
// holds. NodeIDs and ExtensionObjects are accounted for when they are decoded.
var variantValueSizes = [...]int64{
	VariantTypeBoolean:        int64(unsafe.Sizeof(false)),
	VariantTypeSByte:          1,
	VariantTypeByte:           1,
	VariantTypeInt16:          2,
	VariantTypeUInt16:         2,
	VariantTypeInt32:          4,
	VariantTypeUInt32:         4,
	VariantTypeInt64:          8,
	VariantTypeUInt64:         8,
	VariantTypeFloat:          4,
	VariantTypeDouble:         8,
	VariantTypeString:         int64(unsafe.Sizeof("")),
	VariantTypeDateTime:       int64(unsafe.Sizeof(time.Time{})),
	VariantTypeGUID:           int64(unsafe.Sizeof(uuid.UUID{})),
	VariantTypeByteString:     int64(unsafe.Sizeof(ByteString(""))),
	VariantTypeXMLElement:     int64(unsafe.Sizeof(XMLElement(""))),
	VariantTypeNodeID:         0,
	VariantTypeExpandedNodeID: int64(unsafe.Sizeof(ExpandedNodeID{})),
	VariantTypeStatusCode:     int64(unsafe.Sizeof(StatusCode(0))),
	VariantTypeQualifiedName:  int64(unsafe.Sizeof(QualifiedName{})),
	VariantTypeLocalizedText:  int64(unsafe.Sizeof(LocalizedText{})),
	VariantTypeDataValue:      int64(unsafe.Sizeof(DataValue{})),
	VariantTypeDiagnosticInfo: int64(unsafe.Sizeof(DiagnosticInfo{})),
}

// readMatrix reads the values and ArrayDimensions of a multi-dimensional array of
// two or three dimensions, and stores the array in value as nested slices. Once
// both have been read, it returns BadDataTypeIDUnknown if they do not describe
// such an array.
func readMatrix[T any](dec *BinaryDecoder, value *Variant, readValues func(*BinaryDecoder, *[]T) error) error {
	var vals []T
	if err := readValues(dec, &vals); err != nil {
		return BadDecodingError
	}
	var dims []int32
	if err := dec.ReadInt32Array(&dims); err != nil {
		return BadDecodingError
	}
	if err := checkArrayDimensions(dims, len(vals)); err != nil {
		return err
	}
	// the slices that hold the elements.
	headers := int64(dims[0])
	if len(dims) == 3 {
		headers += int64(dims[0]) * int64(dims[1])
	}
	if err := dec.allocate(headers * sliceHeaderSize); err != nil {
		return err
	}
	if len(dims) == 2 {
		d1 := int(dims[1])
		res := make([][]T, dims[0])
		for i := range res {
			res[i], vals = vals[:d1:d1], vals[d1:]
		}
		*value = res
		return nil
	}
	d1, d2 := int(dims[1]), int(dims[2])
	res := make([][][]T, dims[0])
	rows := make([][]T, len(res)*d1)
	for i := range res {
		res[i], rows = rows[:d1:d1], rows[d1:]
		for j := range res[i] {
			res[i][j], vals = vals[:d2:d2], vals[d2:]
		}
	}
	*value = res
	return nil
}

// checkArrayDimensions returns BadDataTypeIDUnknown unless dims are the
// ArrayDimensions of a multi-dimensional array of two or three dimensions with n
// elements.
func checkArrayDimensions(dims []int32, n int) error {
	if len(dims) != 2 && len(dims) != 3 {
		return BadDataTypeIDUnknown
	}
	// limit the number of slices that hold the elements. If the array has elements,
	// there are no more slices at any level than elements. If it has none, as when a
	// dimension is zero, limit them to a fixed number.
	limit := max(int64(n), maxEmptyArraySlices)
	count := int64(1)
	for _, d := range dims {
		if d < 0 {
			return BadDataTypeIDUnknown
		}
		// count <= limit <= math.MaxInt32, so this cannot overflow.
		count *= int64(d)
		if count > limit {
			return BadDataTypeIDUnknown
		}
	}
	if count != int64(n) {
		return BadDataTypeIDUnknown
	}
	return nil
}

// split recursively creates a multi-dimensional array from a set of values
// and some given dimensions.
func split(level, i, j int, dims []int, vals reflect.Value) reflect.Value {
	if level == len(dims)-1 {
		a := vals.Slice(i, j)
		return a
	}

	// split next level
	var elems []reflect.Value
	if vals.Len() > 0 {
		step := (j - i) / dims[level]
		for ; i < j; i += step {
			elems = append(elems, split(level+1, i, i+step, dims, vals))
		}
	} else {
		for k := 0; k < dims[level]; k++ {
			elems = append(elems, split(level+1, 0, 0, dims, vals))
		}
	}

	// now construct the typed slice, i.e. [](type of inner slice)
	innerT := elems[0].Type()
	a := reflect.MakeSlice(reflect.SliceOf(innerT), len(elems), len(elems))
	for k := range elems {
		a.Index(k).Set(elems[k])
	}
	return a
}

// ReadDiagnosticInfo reads a DiagnosticInfo.
func (dec *BinaryDecoder) ReadDiagnosticInfo(value *DiagnosticInfo) error {
	if err := dec.enter(); err != nil {
		return err
	}
	err := dec.readDiagnosticInfo(value)
	dec.leave()
	return dec.limitError(err)
}

func (dec *BinaryDecoder) readDiagnosticInfo(value *DiagnosticInfo) error {
	result := DiagnosticInfo{}
	var b byte
	if err := dec.ReadByte(&b); err != nil {
		return BadDecodingError
	}
	if (b & 1) != 0 {
		if err := dec.allocate(int64(unsafe.Sizeof(int32(0)))); err != nil {
			return err
		}
		result.SymbolicID = new(int32)
		if err := dec.ReadInt32(result.SymbolicID); err != nil {
			return BadDecodingError
		}
	}
	if (b & 2) != 0 {
		if err := dec.allocate(int64(unsafe.Sizeof(int32(0)))); err != nil {
			return err
		}
		result.NamespaceURI = new(int32)
		if err := dec.ReadInt32(result.NamespaceURI); err != nil {
			return BadDecodingError
		}
	}
	if (b & 8) != 0 {
		if err := dec.allocate(int64(unsafe.Sizeof(int32(0)))); err != nil {
			return err
		}
		result.Locale = new(int32)
		if err := dec.ReadInt32(result.Locale); err != nil {
			return BadDecodingError
		}
	}
	if (b & 4) != 0 {
		if err := dec.allocate(int64(unsafe.Sizeof(int32(0)))); err != nil {
			return err
		}
		result.LocalizedText = new(int32)
		if err := dec.ReadInt32(result.LocalizedText); err != nil {
			return BadDecodingError
		}
	}
	if (b & 16) != 0 {
		if err := dec.allocate(int64(unsafe.Sizeof(""))); err != nil {
			return err
		}
		result.AdditionalInfo = new(string)
		if err := dec.ReadString(result.AdditionalInfo); err != nil {
			return BadDecodingError
		}
	}
	if (b & 32) != 0 {
		if err := dec.allocate(int64(unsafe.Sizeof(StatusCode(0)))); err != nil {
			return err
		}
		result.InnerStatusCode = new(StatusCode)
		if err := dec.ReadStatusCode(result.InnerStatusCode); err != nil {
			return BadDecodingError
		}
	}
	if (b & 64) != 0 {
		if err := dec.allocate(int64(unsafe.Sizeof(DiagnosticInfo{}))); err != nil {
			return err
		}
		result.InnerDiagnosticInfo = new(DiagnosticInfo)
		if err := dec.ReadDiagnosticInfo(result.InnerDiagnosticInfo); err != nil {
			return err
		}
	}
	*value = result
	return nil
}

// ReadBooleanArray reads a bool array.
func (dec *BinaryDecoder) ReadBooleanArray(value *[]bool) error {
	temp, err := readArray(dec, 1, (*BinaryDecoder).ReadBoolean)
	if err != nil {
		return err
	}
	*value = temp
	return nil
}

// ReadSByteArray reads a int8 array.
func (dec *BinaryDecoder) ReadSByteArray(value *[]int8) error {
	temp, err := readArray(dec, 1, (*BinaryDecoder).ReadSByte)
	if err != nil {
		return err
	}
	*value = temp
	return nil
}

// ReadByteArray reads a byte array.
func (dec *BinaryDecoder) ReadByteArray(value *[]byte) error {
	n, err := dec.readLength()
	if err != nil {
		return err
	}
	if n < 0 {
		*value = nil
		return nil
	}
	temp, err := dec.readBytes(n)
	if err != nil {
		return err
	}
	*value = temp
	return nil
}

// ReadInt16Array reads a int16 array.
func (dec *BinaryDecoder) ReadInt16Array(value *[]int16) error {
	temp, err := readArray(dec, 2, (*BinaryDecoder).ReadInt16)
	if err != nil {
		return err
	}
	*value = temp
	return nil
}

// ReadUInt16Array reads a uint16 array.
func (dec *BinaryDecoder) ReadUInt16Array(value *[]uint16) error {
	temp, err := readArray(dec, 2, (*BinaryDecoder).ReadUInt16)
	if err != nil {
		return err
	}
	*value = temp
	return nil
}

// ReadInt32Array reads a int32 array.
func (dec *BinaryDecoder) ReadInt32Array(value *[]int32) error {
	temp, err := readArray(dec, 4, (*BinaryDecoder).ReadInt32)
	if err != nil {
		return err
	}
	*value = temp
	return nil
}

// ReadUInt32Array reads a uint32 array.
func (dec *BinaryDecoder) ReadUInt32Array(value *[]uint32) error {
	temp, err := readArray(dec, 4, (*BinaryDecoder).ReadUInt32)
	if err != nil {
		return err
	}
	*value = temp
	return nil
}

// ReadInt64Array reads a int64 array.
func (dec *BinaryDecoder) ReadInt64Array(value *[]int64) error {
	temp, err := readArray(dec, 8, (*BinaryDecoder).ReadInt64)
	if err != nil {
		return err
	}
	*value = temp
	return nil
}

// ReadUInt64Array reads a uint64 array.
func (dec *BinaryDecoder) ReadUInt64Array(value *[]uint64) error {
	temp, err := readArray(dec, 8, (*BinaryDecoder).ReadUInt64)
	if err != nil {
		return err
	}
	*value = temp
	return nil
}

// ReadFloatArray reads a float32 array.
func (dec *BinaryDecoder) ReadFloatArray(value *[]float32) error {
	temp, err := readArray(dec, 4, (*BinaryDecoder).ReadFloat)
	if err != nil {
		return err
	}
	*value = temp
	return nil
}

// ReadDoubleArray reads a float64 array.
func (dec *BinaryDecoder) ReadDoubleArray(value *[]float64) error {
	temp, err := readArray(dec, 8, (*BinaryDecoder).ReadDouble)
	if err != nil {
		return err
	}
	*value = temp
	return nil
}

// ReadStringArray reads a string array.
func (dec *BinaryDecoder) ReadStringArray(value *[]string) error {
	temp, err := readArray(dec, 4, (*BinaryDecoder).ReadString)
	if err != nil {
		return err
	}
	*value = temp
	return nil
}

// ReadDateTimeArray reads a Time array.
func (dec *BinaryDecoder) ReadDateTimeArray(value *[]time.Time) error {
	temp, err := readArray(dec, 8, (*BinaryDecoder).ReadDateTime)
	if err != nil {
		return err
	}
	*value = temp
	return nil
}

// ReadGUIDArray reads a UUID array.
func (dec *BinaryDecoder) ReadGUIDArray(value *[]uuid.UUID) error {
	temp, err := readArray(dec, 16, (*BinaryDecoder).ReadGUID)
	if err != nil {
		return err
	}
	*value = temp
	return nil
}

// ReadByteStringArray reads a ByteString array.
func (dec *BinaryDecoder) ReadByteStringArray(value *[]ByteString) error {
	temp, err := readArray(dec, 4, (*BinaryDecoder).ReadByteString)
	if err != nil {
		return err
	}
	*value = temp
	return nil
}

// ReadXMLElementArray reads a XMLElement array.
func (dec *BinaryDecoder) ReadXMLElementArray(value *[]XMLElement) error {
	temp, err := readArray(dec, 4, (*BinaryDecoder).ReadXMLElement)
	if err != nil {
		return err
	}
	*value = temp
	return nil
}

// ReadNodeIDArray reads a NodeID array.
func (dec *BinaryDecoder) ReadNodeIDArray(value *[]NodeID) error {
	temp, err := readArray(dec, 2, (*BinaryDecoder).ReadNodeID)
	if err != nil {
		return err
	}
	*value = temp
	return nil
}

// ReadExpandedNodeIDArray reads a ExpandedNodeID array.
func (dec *BinaryDecoder) ReadExpandedNodeIDArray(value *[]ExpandedNodeID) error {
	temp, err := readArray(dec, 2, (*BinaryDecoder).ReadExpandedNodeID)
	if err != nil {
		return err
	}
	*value = temp
	return nil
}

// ReadStatusCodeArray reads a StatusCode array.
func (dec *BinaryDecoder) ReadStatusCodeArray(value *[]StatusCode) error {
	temp, err := readArray(dec, 4, (*BinaryDecoder).ReadStatusCode)
	if err != nil {
		return err
	}
	*value = temp
	return nil
}

// ReadQualifiedNameArray reads a QualifiedName array.
func (dec *BinaryDecoder) ReadQualifiedNameArray(value *[]QualifiedName) error {
	temp, err := readArray(dec, 6, (*BinaryDecoder).ReadQualifiedName)
	if err != nil {
		return err
	}
	*value = temp
	return nil
}

// ReadLocalizedTextArray reads a LocalizedText array.
func (dec *BinaryDecoder) ReadLocalizedTextArray(value *[]LocalizedText) error {
	temp, err := readArray(dec, 1, (*BinaryDecoder).ReadLocalizedText)
	if err != nil {
		return err
	}
	*value = temp
	return nil
}

// ReadExtensionObjectArray reads a ExtensionObject array.
func (dec *BinaryDecoder) ReadExtensionObjectArray(value *[]ExtensionObject) error {
	temp, err := readArray(dec, 3, (*BinaryDecoder).ReadExtensionObject)
	if err != nil {
		return err
	}
	*value = temp
	return nil
}

// ReadDataValueArray reads a DataValue array.
func (dec *BinaryDecoder) ReadDataValueArray(value *[]DataValue) error {
	temp, err := readArray(dec, 1, (*BinaryDecoder).ReadDataValue)
	if err != nil {
		return err
	}
	*value = temp
	return nil
}

// ReadVariantArray reads a Variant array.
func (dec *BinaryDecoder) ReadVariantArray(value *[]Variant) error {
	temp, err := readArray(dec, 1, (*BinaryDecoder).ReadVariant)
	if err != nil {
		return err
	}
	*value = temp
	return nil
}

// ReadDiagnosticInfoArray reads a DiagnosticInfo array.
func (dec *BinaryDecoder) ReadDiagnosticInfoArray(value *[]DiagnosticInfo) error {
	temp, err := readArray(dec, 1, (*BinaryDecoder).ReadDiagnosticInfo)
	if err != nil {
		return err
	}
	*value = temp
	return nil
}

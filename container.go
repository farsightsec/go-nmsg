/*
 * Copyright (c) 2017,2018 by Farsight Security, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package nmsg

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"

	"google.golang.org/protobuf/proto"
)

const (
	nmsgVersion      = 2
	nmsgFlagZlib     = 1
	nmsgFlagFragment = 2
	headerSize       = 10
)

var (
	nmsgMagic         = [4]byte{'N', 'M', 'S', 'G'}
	errBadMagic       = errors.New("Bad NMSG Magic Number")
	containerOverhead = 10
	fragmentOverhead  = 10 + 4 + 24
)

type containerHeader struct {
	Magic          [4]byte
	Flags, Version byte
	Length         uint32
}

// isCompressed() and isFragmented() are helper functions for readability.
func (h *containerHeader) isCompressed() bool {
	return h.Flags&nmsgFlagZlib != 0
}

func (h *containerHeader) isFragmented() bool {
	return h.Flags&nmsgFlagFragment != 0
}

// A Container encapsulates an Nmsg envelope, and maintains metadata for
// sizing containers as payloads are added.
type Container struct {
	// Maximum size of a container. AddPayload attempts to keep the container
	// under this size.
	maxSize int
	// Maximum size of fragment or container. Any containers larger than this
	// will be fragmented by WriteTo.
	writeSize int
	// If true, compress container contents before writing.
	compress bool
	// If true, container was populated from compressed data
	// This is primarily used in fragment reassembly to detect whether the
	// fragmented data was compressed prior to fragmentation.
	isCompressed bool
	// If nonzero, an estimate of the effectiveness of compression, expressed
	// as compressedSize / uncompressedSize. Default: 0.5
	compressionRatio float32
	// The current estimated size of the serialized data, before compression
	size int
	Nmsg
	*NmsgFragment
}

// NewContainer creates a new empty NMSG container.
func NewContainer() *Container {
	c := &Container{size: containerOverhead}
	c.SetMaxSize(0, 0)
	return c
}

// SetMaxSize sets the maximum size (including Marshaling overhead,
// container header, and anticipated compression ratio) of a container.
// AddPayload attempts to keep the container within this size.
//
// writeSize specifies the maximum size of containers or fragments.
// Containers larger than writeSize will be written as fragments instead
// of single containers.
//
// A writeSize value of 0 is treated as equal to size.
func (c *Container) SetMaxSize(size, writeSize int) {
	if size < MinContainerSize {
		size = MinContainerSize
	}
	if size > MaxContainerSize {
		size = MaxContainerSize
	}
	if writeSize < size {
		writeSize = size
	}
	c.maxSize = size
	c.writeSize = writeSize
}

// SetCompression instructs WriteTo to write containers with compressed
// (if true) or uncompressed (if false) contents.
func (c *Container) SetCompression(compress bool) {
	c.compress = compress
}

// SetCompressionRatio sets an estimated compression ratio for the data.
// The default value is 2.0
func (c *Container) SetCompressionRatio(ratio float32) {
	c.compressionRatio = ratio
}

// SetSequenced sets or unsets sequencing on the container stream.
// The sequence number is updated every time WriteTo() is called.
func (c *Container) SetSequenced(sequenced bool) {
	if sequenced {
		seqid := uint64(rand.Uint32()) << 32
		seqid |= uint64(rand.Uint32())
		c.Nmsg.SequenceId = proto.Uint64(seqid)
		c.Nmsg.Sequence = proto.Uint32(0)
	} else {
		c.Nmsg.SequenceId = nil
		c.Nmsg.Sequence = nil
	}
}

// AddPayload adds the supplied NmsgPayload to the Container if possible.
//
// The return value 'full' is true if the container is full and needs to
// be emptied with WriteTo().
//
// The return value 'ok' is true if the payload was successfully added to
// the container, otherwise, AddPayload() must be called again after WriteTo().
//
// Both ok and full may be true if the payload is larger than the container's
// MaxSize, or if the container is full after adding the payload.
func (c *Container) AddPayload(p *NmsgPayload) (ok, full bool) {

	seqSize := 0

	if c.Nmsg.Sequence != nil && c.Nmsg.SequenceId != nil {
		seqSize = 18 // 6 + 12 bytes for protobuf-encoded sequence and sequenceId values
	}

	limit := c.maxSize
	if c.compress {
		if c.compressionRatio > 0 {
			limit = int(float32(limit) * c.compressionRatio)
		} else {
			limit *= 2
		}
	}
	ps := p.payloadSize()

	if c.size+ps+seqSize > limit {
		full = true
		if c.size != containerOverhead {
			return
		}
	}

	ok = true
	c.size += ps
	c.Nmsg.Payloads = append(c.Nmsg.Payloads, p)
	c.Nmsg.PayloadCrcs = append(c.Nmsg.PayloadCrcs, nmsgCRC(p.Payload))

	return
}

// Reset discards payloads and crcs from the Container
func (c *Container) Reset() {
	c.Nmsg.Payloads = c.Nmsg.Payloads[:0]
	c.Nmsg.PayloadCrcs = c.Nmsg.PayloadCrcs[:0]
	c.NmsgFragment = nil
}

// WriteTo writes the Container to Writer w. If the
// container requires fragmentation, it will call
// w.Write() multiple times.
func (c *Container) WriteTo(w io.Writer) (int64, error) {
	var buf bytes.Buffer

	header := containerHeader{
		Magic:   nmsgMagic,
		Version: nmsgVersion,
	}

	defer c.Reset()

	b, err := proto.Marshal(&c.Nmsg)
	if err != nil {
		return 0, err
	}

	if c.compress {
		b, err = zbufDeflate(b)
		if err != nil {
			return 0, err
		}
		header.Flags |= nmsgFlagZlib
	}

	header.Length = uint32(len(b))
	if c.Nmsg.Sequence != nil {
		*c.Nmsg.Sequence++
	}
	c.size = containerOverhead

	if len(b)+containerOverhead > c.writeSize {
		return c.writeFragments(w, b)
	}

	if err = binary.Write(&buf, binary.BigEndian, &header); err != nil {
		return 0, err
	}

	if _, err = buf.Write(b); err != nil {
		return 0, err
	}

	return buf.WriteTo(w)
}

func (c *Container) writeFragments(w io.Writer, b []byte) (int64, error) {
	header := containerHeader{
		Magic:   nmsgMagic,
		Version: nmsgVersion,
		Flags:   nmsgFlagFragment,
	}

	if c.compress {
		header.Flags |= nmsgFlagZlib
	}

	fragSize := c.writeSize - fragmentOverhead
	lastFrag := len(b) / fragSize
	fragID := rand.Uint32()

	nf := NmsgFragment{
		Id:      proto.Uint32(fragID),
		Current: proto.Uint32(uint32(0)),
		Last:    proto.Uint32(uint32(lastFrag)),
		Crc:     proto.Uint32(nmsgCRC(b)),
	}

	var written int64
	for i := 0; i <= lastFrag; i++ {
		var buf bytes.Buffer

		fblen := len(b)
		if fblen > fragSize {
			fblen = fragSize
		}

		*nf.Current = uint32(i)
		nf.Fragment = b[:fblen]
		b = b[fblen:]

		fbytes, err := proto.Marshal(&nf)
		if err != nil {
			return written, err
		}

		header.Length = uint32(len(fbytes))
		if err = binary.Write(&buf, binary.BigEndian, header); err != nil {
			return written, err
		}

		if _, err = buf.Write(fbytes); err != nil {
			return written, err
		}

		n, err := buf.WriteTo(w)
		if err != nil {
			return written, err
		}
		written += n
	}
	return written, nil
}

// ReadFrom Reads a Container from the given io.Reader. It returns the
// number of container bytes read on success.
func (c *Container) ReadFrom(r io.Reader) (n int64, err error) {
	/*
	 * The bytes.Buffer Grow() method may panic with ErrTooLarge.
	 * We catch this panic (and any other error panic()s and return
	 * an error.
	 */
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			if err, ok = r.(error); !ok {
				err = fmt.Errorf("nmsg.Container ReadFrom: panic %v", r)
			}
		}
	}()
	var buf bytes.Buffer
	var h containerHeader
	if n, err = io.CopyN(&buf, r, headerSize); err != nil {
		return n, err
	}

	err = binary.Read(&buf, binary.BigEndian, &h)
	if err != nil {
		return n, &dataError{err}
	}
	if h.Magic != nmsgMagic {
		return 0, &dataError{errBadMagic}
	}

	buf.Grow(int(h.Length))
	if n, err = io.CopyN(&buf, r, int64(h.Length)); err != nil {
		return int64(buf.Len()), err
	}

	// err = c.fromBytesHeader(buf.Bytes(), &h)
	err = c.fromNmsgBytes(buf.Bytes(), h.isCompressed(), h.isFragmented())
	if err != nil {
		err = &dataError{err}
	}
	return int64(buf.Len()), err
}

// FromBytes parses the given buffer as an NMSG container and stores
// the result in the receiver *Container.
func (c *Container) FromBytes(b []byte) error {
	var h containerHeader
	buf := bytes.NewBuffer(b)
	err := binary.Read(buf, binary.BigEndian, &h)
	if err != nil {
		return err
	}
	if h.Magic != nmsgMagic {
		return errBadMagic
	}

	return c.fromNmsgBytes(buf.Bytes(), h.isCompressed(), h.isFragmented())
}

// fromNmsgBytes parses the contents (b) of an NMSG container, according to
// whether the container contents are compressed, fragmented, or both.
func (c *Container) fromNmsgBytes(b []byte, compressed, fragmented bool) error {
	var err error
	cbytes := b
	c.isCompressed = compressed
	if compressed {
		cbytes, err = zbufInflate(b)
		if err != nil {
			return err
		}
	}

	if fragmented {
		c.NmsgFragment = &NmsgFragment{}
		return proto.Unmarshal(cbytes, c.NmsgFragment)
	}

	c.NmsgFragment = nil
	return proto.Unmarshal(cbytes, &c.Nmsg)
}

/*
 * Copyright (c) 2017 by Farsight Security, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package nmsg_test

// These tests verify container compatibility between C libnmsg (wrapped in
// cgo-nmsg) and go-nmsg, both with and without compression.

import (
	"bytes"
	"log"
	"testing"
	"fmt"

	cnmsg "github.com/farsightsec/go-nmsg/cgo-nmsg"
	"github.com/farsightsec/go-nmsg"
	"github.com/farsightsec/go-nmsg/nmsg_base"
)

func compare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestContainerGoCgoUnpack(t *testing.T) {
	b := new(bytes.Buffer)
	c := nmsg.NewContainer()
	c.SetMaxSize(nmsg.MinContainerSize, nmsg.MinContainerSize)
	c.AddPayload(testGoMessage(100))
	c.WriteTo(b)

	m, err := cnmsg.UnpackContainer(b.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	if len(m) != 1 {
		t.Fatalf("message count mismatch %d != 1", len(m))
	}

	if checkCgoMessage(m[0], 100) {
		return
	}

	t.Error("payload mismatch")
}

func TestContainerGoCgoUnpackCompress(t *testing.T) {
	b := new(bytes.Buffer)
	c := nmsg.NewContainer()
	c.SetCompression(true)
	c.SetMaxSize(nmsg.MinContainerSize, nmsg.MinContainerSize)
	c.AddPayload(testGoMessage(100))
	c.WriteTo(b)

	byt := b.Bytes()

	m, err := cnmsg.UnpackContainer(byt)
	if err != nil {
		t.Fatal(err)
	}

	if len(m) != 1 {
		t.Fatalf("message count mismatch %d != 1", len(m))
	}

	if checkCgoMessage(m[0], 100) {
		return
	}

	t.Error("payload mismatch")
}

func testCgoMessage(size int) *cnmsg.Message {
	mod := cnmsg.MessageModLookupByName("base", "encode")
	if mod == nil {
		log.Fatal("module not found")
	}
	msg := cnmsg.NewMessage(mod)
	if err := msg.SetEnumField("type", 0, "TEXT"); err != nil {
		log.Fatal(err)
	}

	if err := msg.SetBytesField("payload", 0, make([]byte, size)); err != nil {
		log.Fatal(err)
	}
	return msg
}

func checkCgoMessage(m *cnmsg.Message, size int) bool {
	b, err := m.GetBytesField("payload", 0)
	if err != nil {
		return false
	}
	return compare(b, make([]byte, size))
}

func testGoMessage(size int) *nmsg.NmsgPayload {
	m := new(nmsg_base.Encode)
	m.Payload = make([]byte, size)
	m.Type = nmsg_base.EncodeType_TEXT.Enum()
	p, err := nmsg.Payload(m)
	if err != nil {
		log.Fatal(err)
	}
	return p
}

func checkGoMessage(m nmsg.Message, size int) bool {
	enc, ok := m.(*nmsg_base.Encode)

	if !ok {
		log.Printf("type mismatch: %T != *nmsg_base.Encode", m)
		return false
	}
	return compare(enc.GetPayload(), make([]byte, size))
}

func TestContainerCgoGoUnpack(t *testing.T) {
	c := cnmsg.NewContainer(&cnmsg.ContainerConfig{
		Size: cnmsg.BufferSizeMin,
	})
	c.Add(testCgoMessage(100))

	i := nmsg.NewInput(bytes.NewReader(c.Bytes()), cnmsg.BufferSizeMin)
	p, err := i.Recv()
	if err != nil {
		t.Fatal(err)
	}

	m, err := p.Message()
	if err != nil {
		t.Fatal(err)
	}

	if checkGoMessage(m, 100) {
		return
	}

	t.Error("payload mismatch")
}

func TestContainerCgoGoUnpackCompress(t *testing.T) {
	c := cnmsg.NewContainer(&cnmsg.ContainerConfig{
		Size:     cnmsg.BufferSizeMin,
		Compress: true,
	})
	c.Add(testCgoMessage(100))

	byt := c.Bytes()
	i := nmsg.NewInput(bytes.NewReader(byt), cnmsg.BufferSizeMin)
	p, err := i.Recv()
	if err != nil {
		t.Fatal(err)
	}

	m, err := p.Message()
	if err != nil {
		t.Fatal(err)
	}

	if checkGoMessage(m, 100) {
		return
	}

	t.Error("payload mismatch")
}

func TestContainerFromBytes(t *testing.T) {
	testnmsg := []byte {
		0x4e, 0x4d, 0x53, 0x47, 0x00, 0x02, 0x00, 0x00, 0x00, 0xbf, 0x0a, 0xb7, 0x01, 0x08, 0x02, 0x10,
		0x05, 0x18, 0xb3, 0xc6, 0xd8, 0xec, 0x05, 0x25, 0x77, 0x91, 0xfd, 0x34, 0x2a, 0x9f, 0x01, 0x0a,
		0x1b, 0x15, 0x6e, 0x61, 0x70, 0x65, 0x72, 0x76, 0x69, 0x6c, 0x6c, 0x65, 0x70, 0x75, 0x6d, 0x70,
		0x6b, 0x69, 0x6e, 0x72, 0x61, 0x63, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x10, 0xc8, 0xc5, 0xd8,
		0xec, 0x05, 0x1a, 0x1b, 0x15, 0x6e, 0x61, 0x70, 0x65, 0x72, 0x76, 0x69, 0x6c, 0x6c, 0x65, 0x70,
		0x75, 0x6d, 0x70, 0x6b, 0x69, 0x6e, 0x72, 0x61, 0x63, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x20,
		0x02, 0x28, 0x01, 0x3a, 0x12, 0x06, 0x6e, 0x73, 0x31, 0x30, 0x38, 0x39, 0x06, 0x75, 0x69, 0x2d,
		0x64, 0x6e, 0x73, 0x02, 0x64, 0x65, 0x00, 0x3a, 0x13, 0x06, 0x6e, 0x73, 0x31, 0x30, 0x34, 0x37,
		0x06, 0x75, 0x69, 0x2d, 0x64, 0x6e, 0x73, 0x03, 0x62, 0x69, 0x7a, 0x00, 0x3a, 0x13, 0x06, 0x6e,
		0x73, 0x31, 0x30, 0x39, 0x38, 0x06, 0x75, 0x69, 0x2d, 0x64, 0x6e, 0x73, 0x03, 0x63, 0x6f, 0x6d,
		0x00, 0x3a, 0x13, 0x06, 0x6e, 0x73, 0x31, 0x31, 0x31, 0x35, 0x06, 0x75, 0x69, 0x2d, 0x64, 0x6e,
		0x73, 0x03, 0x6f, 0x72, 0x67, 0x00, 0x82, 0x01, 0x05, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x38, 0xcf,
		0x85, 0xe8, 0x8d, 0x0a, 0x10, 0xaf, 0xb2, 0x9b, 0x4b,
	}

	c := nmsg.NewContainer()
	if err := c.FromBytes(testnmsg); err != nil {
		t.Errorf("deserialization of good container created error: %v", err)
	}

	c.Reset()

	c.SetCompression(true)
	c.SetCompressionRatio(2.0)
	c.SetMaxSize(nmsg.MaxContainerSize * 2, nmsg.MinContainerSize)
	c.SetSequenced(false)

	payload := testGoMessage(1000)
	payload.SetSource(123)
	payload.SetOperator(13)
	payload.SetGroup(31337)
	c.AddPayload(payload)

	b := new(bytes.Buffer)
	c.WriteTo(b)

	i := nmsg.NewInput(bytes.NewReader(b.Bytes()), nmsg.MaxContainerSize)

	if p, err := i.Recv(); err != nil {
		t.Errorf("error receiving fabricated nmsg payload: %v", err)
	} else if p.GetSource() != payload.GetSource() {
		t.Errorf("input/output packet mismatch on src,op,grp: expected %v, %v, %v; received %v, %v, %v",
			payload.GetSource(), payload.GetOperator(), payload.GetGroup(),
			p.GetSource(), p.GetOperator(), p.GetGroup())
	}

	b = new(bytes.Buffer)

	if nw, err := b.Write(testnmsg[0:12]); err != nil || nw != 12 {
		t.Errorf("error serializing test nmsg container: %v", err)
	} else {
		c.Reset()

		if _, err := c.ReadFrom(b); err == nil {
			t.Error("expected bad nmsg container to produce read error")
		}
	}

	o4 := testnmsg[4]
	testnmsg[4] = 0xff

	b = new(bytes.Buffer)

	if nw, err := b.Write(testnmsg); err != nil || nw != len(testnmsg) {
		t.Errorf("error serializing test nmsg container: %v", err)
	} else {
		c.Reset()

		if _, err := c.ReadFrom(b); err == nil {
			t.Error("expected bad nmsg container to produce read error")
		}
	}

	testnmsg[4] = o4
	testnmsg[0] = 0xff

	if err := c.FromBytes(testnmsg); err == nil {
		t.Errorf("deserialization of bad container produced no error")
	}

	b = new(bytes.Buffer)

	if nw, err := b.Write(testnmsg); err != nil || nw != len(testnmsg) {
		t.Errorf("error serializing test nmsg container: %v", err)
	} else {
		c.Reset()

		if _, err := c.ReadFrom(b); err == nil {
			t.Error("expected bad nmsg container to produce read error")
		} else if nmsg.IsDataError(err) {
			fmt.Printf("got expected data error: %v\n", err)
		} else {
			 t.Errorf("expected nmsg data error but got: %v", err)
		}
	}

}

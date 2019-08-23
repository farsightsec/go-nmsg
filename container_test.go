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

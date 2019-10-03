/*
 * Copyright (c) 2017 by Farsight Security, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package nmsg_test

import (
	"testing"

	"github.com/farsightsec/go-nmsg"
	"github.com/golang/protobuf/proto"
)

func testMessage(length int) nmsg.Message {
	return &testMsg{Bytes: make([]byte, length)}
}

func testPayload(length int) *nmsg.NmsgPayload {
	p, err := nmsg.Payload(testMessage(length))
	if err != nil {
		return nil
	}
	return p
}

type testMsg struct {
	Bytes []byte `protobuf:"bytes,2,opt,name=bytes"`
}

func (t *testMsg) GetVid() uint32     { return 10 }
func (t *testMsg) GetMsgtype() uint32 { return 20 }

func (t *testMsg) Reset()         { *t = testMsg{} }
func (t *testMsg) String() string { return proto.CompactTextString(t) }
func (t *testMsg) ProtoMessage()  {}

func init() {
	nmsg.Register(&testMsg{})
}

func TestRegister(t *testing.T) {
	msg, err := nmsg.NewMessage(10000, 20)
	if err == nil {
		t.Error("expected new message with invalid vendor ID to generate error")
	} else if err.Error() == "" {
		t.Error("expected new message with invalid vendor ID to produce error string")
	}

	msg, err = nmsg.NewMessage(10, 20000)
	if err == nil {
		t.Error("expected new message with invalid msgtype to generate error")
	} else if err.Error() == "" {
		t.Error("expected new message with invalid msgtype to produce error string")
	}

	msg, err = nmsg.NewMessage(10, 20)
	if err != nil {
		t.Error(err)
	}
	if _, ok := msg.(*testMsg); !ok {
		t.Errorf("NewMessage returned wrong type")
	}
}

func TestPayload(t *testing.T) {
	p, err := nmsg.Payload(testMessage(1000))
	if err != nil {
		t.Errorf("nmsg.Payload(): %s", err)
	}

	m, err := p.Message()
	if err != nil {
		t.Error(err)
	}

	if tp, ok := m.(*testMsg); !ok {
		t.Errorf("Wrong type from payload")
	} else if len(tp.Bytes) != 1000 {
		t.Error("decode failed")
	}
}

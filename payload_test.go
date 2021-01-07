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
)

func testMessage(length int) nmsg.Message {
	return &TestMessage{Bytes: make([]byte, length)}
}

func testPayload(length int) *nmsg.NmsgPayload {
	p, err := nmsg.Payload(testMessage(length))
	if err != nil {
		return nil
	}
	return p
}

func (t *TestMessage) GetVid() uint32     { return 10 }
func (t *TestMessage) GetMsgtype() uint32 { return 20 }

func init() {
	nmsg.Register(&TestMessage{})
}

func TestRegister(t *testing.T) {
	msg, err := nmsg.NewMessage(10, 20)
	if err != nil {
		t.Error(err)
	}
	if _, ok := msg.(*TestMessage); !ok {
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

	if tp, ok := m.(*TestMessage); !ok {
		t.Errorf("Wrong type from payload")
	} else if len(tp.Bytes) != 1000 {
		t.Error("decode failed")
	}
}

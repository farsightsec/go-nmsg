/*
 * Copyright (c) 2017 by Farsight Security, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package nmsg_test

import (
	"bytes"
	"testing"

	"github.com/farsightsec/go-nmsg"
)

func TestZlib(t *testing.T) {
	b := new(bytes.Buffer)
	m := testMessage(20)
	p, err := nmsg.Payload(m)
	if err != nil {
		t.Fatal(err)
	}
	out := nmsg.UnbufferedOutput(b)
	out.SetCompression(true)
	out.SetMaxSize(1500, 0)
	if err := out.Send(p); err != nil {
		t.Fatal(err)
	}

	inp := nmsg.NewInput(b, 1500)
	p, err = inp.Recv()
	if err != nil {
		t.Fatal(err)
	}
	mm, err := p.Message()
	if err != nil {
		t.Fatal(err)
	}
	mi, ok := mm.(*testMsg)
	if !ok {
		t.Error("received message of wrong type")
	}
	if len(mi.Bytes) != len(m.(*testMsg).Bytes) {
		t.Error("received message of wrong length")
	}
	for i := range mi.Bytes {
		if mi.Bytes[i] != 0 {
			t.Fatal("received message with wrong data")
		}
	}

}

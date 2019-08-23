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
	"io"
	"math"
	"testing"

	"github.com/farsightsec/go-nmsg"
)

func testReader(t *testing.T, n, size, mtu int) io.Reader {
	buf := new(bytes.Buffer)
	// nw := nmsg.NewWriter(w, mtu)
	o := nmsg.BufferedOutput(buf)
	o.SetMaxSize(mtu, 0)
	o.SetSequenced(true)

	p, err := nmsg.Payload(testMessage(size))
	if err != nil {
		t.Error(err.Error())
		return nil
	}

	for i := 0; i < n; i++ {
		o.Send(p)
	}

	o.Close()

	t.Logf("testReader: buf = %d bytes (%d, %d, %d)", buf.Len(), n, size, mtu)
	return buf
}

func TestInput(t *testing.T) {
	for _, mtu := range []int{0, 512, 1500} {
		for _, n := range []int{1, 10, 100} {
			for _, size := range []int{64, 256, 4096} {
				i := nmsg.NewInput(testReader(t, n, size, mtu), mtu)
				if i != nil {
					c := 0
					for {
						_, err := i.Recv()
						if err != nil {
							if err != io.EOF {
								t.Error(err)
							}
							break
						}
						c++
					}
					if c < n {
						t.Errorf("(%d,%d,%d) expected %d, received %d", n, size, mtu, n, c)
					}
				}
			}
		}
	}
}

func TestInputFragExpire(t *testing.T) {
	// Fragment expiration is not checked here, only in
	// coverage.
	var readers []io.Reader
	npayloads := 10
	payloadSize := 512
	mtu := 512
	for i := 0; i < 1000; i++ {
		readers = append(readers, testReader(t, npayloads,
			payloadSize, mtu))
	}
	inp := nmsg.NewInput(io.MultiReader(readers...), 512)
	var count int
	for ; ; count++ {
		_, err := inp.Recv()
		if err != nil {
			break
		}
	}
	if count != npayloads*1000 {
		t.Errorf("missed input, received %d payloads", count)
	}
}

func testLoss(t *testing.T, r io.Reader, loss uint64, title string) {
	t.Helper()
	i := nmsg.NewInput(r, nmsg.MaxContainerSize)
	for {
		if _, err := i.Recv(); err != nil {
			break
		}
	}
	stats := i.Stats()
	if stats.LostContainers != loss {
		t.Errorf("%s: lost %d (expected %d)", title, stats.LostContainers, loss)
	}
}

func TestInputSequenceLoss1(t *testing.T) {
	var buf bytes.Buffer
	c := nmsg.NewContainer()

	c.SetSequenced(true)
	c.WriteTo(&buf)
	c.WriteTo(&buf)
	*c.Nmsg.Sequence++ // skip one
	c.WriteTo(&buf)

	testLoss(t, &buf, 1, "drop 1")
}

func TestInputSequenceInterleaveLoss1(t *testing.T) {
	var buf bytes.Buffer

	c1 := nmsg.NewContainer()
	c2 := nmsg.NewContainer()
	c1.SetSequenced(true)
	c2.SetSequenced(true)

	c1.WriteTo(&buf)
	c2.WriteTo(&buf)
	c2.WriteTo(&buf)
	c1.WriteTo(&buf)
	c2.WriteTo(&buf)
	*c1.Nmsg.Sequence++
	c1.WriteTo(&buf)
	c2.WriteTo(&buf)
	testLoss(t, &buf, 1, "interleaved, drop 1")
}

func TestInputSequenceWrap(t *testing.T) {
	var buf bytes.Buffer

	c := nmsg.NewContainer()
	c.SetSequenced(true)
	*c.Nmsg.Sequence = math.MaxUint32 - 1
	t.Log("sequence", c.Nmsg.GetSequence())
	c.WriteTo(&buf)
	t.Log("sequence", c.Nmsg.GetSequence())
	*c.Nmsg.Sequence++
	t.Log("sequence", c.Nmsg.GetSequence())
	c.WriteTo(&buf)
	t.Log("sequence", c.Nmsg.GetSequence())
	testLoss(t, &buf, 1, "wrapped, drop 1")
}

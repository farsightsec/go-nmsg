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
	"errors"
	"testing"
	"time"

	"github.com/farsightsec/go-nmsg"
)

type countWriter struct {
	count, total int
	closed       bool
	t            *testing.T
}

// Testing output.

// countWriter Implements io.WriteCloser, plus a Count() method returning
// how many times it has been called and a Total() method returning the
// number of bytes written.

func (w *countWriter) Count() int { return w.count }
func (w *countWriter) Total() int { return w.total }

func (w *countWriter) Write(b []byte) (int, error) {
	w.t.Logf("Writing %d bytes", len(b))
	w.count++
	w.total += len(b)
	return len(b), nil
}

func newCountWriter(t *testing.T) *countWriter {
	return &countWriter{t: t}
}

// bufWriter augments bytes.Buffer with a Clos() method to
// satisfy io.WriteCloser
type bufWriter struct {
	*bytes.Buffer
}

func newBufWriter() *bufWriter {
	return &bufWriter{new(bytes.Buffer)}
}

func TestUnBufferedOutput(t *testing.T) {
	c := newCountWriter(t)
	p, err := nmsg.Payload(testMessage(1000))
	if err != nil {
		t.Errorf(err.Error())
	}
	o := nmsg.UnbufferedOutput(c)
	o.SetMaxSize(1500, 0)
	if err := o.Send(p); err != nil {
		t.Errorf(err.Error())
	}
	if c.Count() < 1 {
		t.Errorf("No write occurred")
	}
	if c.Total() < 1000 {
		t.Errorf("Write was too short")
	}
	if err := o.Close(); err != nil {
		t.Errorf("Close failed")
	}

}

func TestBufferedOutput(t *testing.T) {
	c := newCountWriter(t)
	o := nmsg.BufferedOutput(c)
	o.SetMaxSize(1500, 0)
	o.SetSequenced(true)

	// this should go in the buffer, and not be written
	if err := o.Send(testPayload(800)); err != nil {
		t.Errorf(err.Error())
	}
	if c.Count() > 0 {
		t.Error("Buffer did not suppress write")
	}

	// this should flush the buffer, causing one write,
	// then go into the buffer, not causing a second write.
	if err := o.Send(testPayload(800)); err != nil {
		t.Errorf(err.Error())
	}
	if c.Count() < 1 {
		t.Error("Buffer did not write")
	}
	if c.Count() > 1 {
		t.Error("Buffer did not suppress write")
	}

	// this should flush the buffer, causing one write,
	// then bypass the buffer and be written in two fragments
	if err := o.Send(testPayload(1700)); err != nil {
		t.Errorf(err.Error())
	}
	if err := o.Close(); err != nil {
		t.Errorf(err.Error())
	}
	if c.Count() < 4 {
		t.Errorf("Missing writes: %d should be 4", c.Count())
	}
	if c.Count() > 4 {
		t.Error("Extra writes")
	}
}

func TestBufferedOutputNoConfig(t *testing.T) {
	c := newCountWriter(t)
	o := nmsg.BufferedOutput(c)

	// this should go in the buffer with the default
	// MinContainerSize maximum, and not be written
	if err := o.Send(testPayload(300)); err != nil {
		t.Errorf(err.Error())
	}
	if c.Count() > 0 {
		t.Error("Buffer did not suppress write")
	}

	// this should flush the buffer, causing one write,
	// then go into the buffer, not causing a second write.
	if err := o.Send(testPayload(300)); err != nil {
		t.Errorf(err.Error())
	}
	if c.Count() < 1 {
		t.Error("Buffer did not write")
	}
	if c.Count() > 1 {
		t.Error("Buffer did not suppress write")
	}

	// this should flush the buffer, causing one write,
	// then bypass the buffer and be written in two fragments
	if err := o.Send(testPayload(600)); err != nil {
		t.Errorf(err.Error())
	}
	if err := o.Close(); err != nil {
		t.Errorf(err.Error())
	}
	if c.Count() < 4 {
		t.Errorf("Missing writes: %d should be 4", c.Count())
	}
	if c.Count() > 4 {
		t.Error("Extra writes")
	}
}

func TestTimedBufferedOutput(t *testing.T) {
	c := newCountWriter(t)
	o := nmsg.TimedBufferedOutput(c, 100*time.Millisecond)
	o.SetMaxSize(1500, 0)
	o.SetSequenced(true)

	// This should wait about 100ms to send
	if err := o.Send(testPayload(100)); err != nil {
		t.Error(err.Error())
	}
	if c.Count() > 0 {
		t.Error("Write not delayed")
	}

	time.Sleep(110 * time.Millisecond)

	if c.Count() < 1 {
		t.Error("Write timed out.")
	}

	if err := o.Close(); err != nil {
		t.Error(err.Error())
	}
}

func TestTimedBufferedOutputNoConfig(t *testing.T) {
	c := newCountWriter(t)
	o := nmsg.TimedBufferedOutput(c, 100*time.Millisecond)
	o.SetSequenced(true)

	// This should wait about 100ms to send
	if err := o.Send(testPayload(100)); err != nil {
		t.Error(err.Error())
	}
	if c.Count() > 0 {
		t.Error("Write not delayed")
	}

	time.Sleep(110 * time.Millisecond)

	if c.Count() < 1 {
		t.Error("Write timed out.")
	}

	if err := o.Close(); err != nil {
		t.Error(err.Error())
	}

	for i := 0; i < 10; i++ {
		o.Send(testPayload(100))
	}
	time.Sleep(110 * time.Millisecond)

	if c.Count() < 2 {
		t.Error("Writes timed out")
	}
}

func TestTimedBufferReset(t *testing.T) {
	c := newCountWriter(t)
	o := nmsg.TimedBufferedOutput(c, 100*time.Millisecond)
	o.SetMaxSize(1500, 0)
	o.SetSequenced(true)

	if err := o.Send(testPayload(750)); err != nil {
		t.Error(err.Error())
	}
	time.Sleep(50 * time.Millisecond)
	// This should trigger a write, leave this payload in
	// the buffer, and reset the timer for another 100ms.
	if err := o.Send(testPayload(750)); err != nil {
		t.Error(err.Error())
	}

	time.Sleep(25 * time.Millisecond)

	if c.Count() < 1 {
		t.Error("Write failed to happen")
	}
	if c.Count() > 1 {
		t.Error("Spurious write happened")
	}

	// Check at start + 100ms, to make sure the buffer didn't fire twice
	time.Sleep(25 * time.Millisecond)
	if c.Count() > 1 {
		t.Error("premature second write")
	}

	// Check in after start + 150ms, second write should have happened.
	time.Sleep(55 * time.Millisecond)
	if c.Count() < 2 {
		t.Error("second write late")
	}

	time.Sleep(55 * time.Millisecond)
	// The previous write caused the timer to expire, and it will need to
	// be restarted. Test that code path with one more sequence of Sends
	// which will force a flush.
	for i := 0; i < 3; i++ {
		if err := o.Send(testPayload(750)); err != nil {
			t.Error(err.Error())
		}
	}

	time.Sleep(25 * time.Millisecond)

	if c.Count() < 3 {
		t.Error("third write late")
	}

	time.Sleep(80 * time.Millisecond)
	if c.Count() < 4 {
		t.Error("Final write late")
	}

	o.Close()
}

type countdownWriter int

func (c *countdownWriter) Write(b []byte) (int, error) {
	if *c > 0 {
		(*c)--
		return len(b), nil
	}
	return 0, errors.New("writer finished")
}

func newCountdownWriter(n int) *countdownWriter {
	c := countdownWriter(n)
	return &c
}

func TestTimedBufferedOutputError(t *testing.T) {
	cw := newCountdownWriter(1)

	o := nmsg.TimedBufferedOutput(cw, 100*time.Millisecond)
	o.SetMaxSize(1500, 0)
	if err := o.Send(testPayload(750)); err != nil {
		t.Error(err.Error())
	}
	if err := o.Send(testPayload(750)); err != nil {
		t.Error(err.Error())
	}
	// write should occur above, and leave one payload in buffer,
	// to be flushed by the next, which should return an error
	if err := o.Send(testPayload(750)); err == nil {
		t.Error("no error")
	}
}

func TestTimedBufferedOutputTimedError(t *testing.T) {
	cw := newCountdownWriter(0)
	o := nmsg.TimedBufferedOutput(cw, 100*time.Millisecond)
	if err := o.Send(testPayload(100)); err != nil {
		t.Error(err)
	}
	<-time.After(110 * time.Millisecond)
	// At this point, a timer-driven flush should have triggered
	// a writer error, which should be returned on the next Send.
	if err := o.Send(testPayload(100)); err == nil {
		t.Error("no error")
	}
}

type nullwriter struct{}

func (n nullwriter) Write(b []byte) (int, error) { return len(b), nil }

func BenchmarkUnbufferedOutput(b *testing.B) {
	var w nullwriter
	p, err := nmsg.Payload(testMessage(1000))
	if err != nil {
		b.Error(err.Error())
	}
	o := nmsg.UnbufferedOutput(w)
	o.SetMaxSize(1500, 0)
	for i := 0; i < b.N; i++ {
		if err := o.Send(p); err != nil {
			b.Error(err.Error())
			return
		}
	}
	o.Close()
}

func BenchmarkBufferedOutput(b *testing.B) {
	var w nullwriter
	p, err := nmsg.Payload(testMessage(1000))
	if err != nil {
		b.Error(err.Error())
	}
	o := nmsg.BufferedOutput(w)
	o.SetMaxSize(1500, 0)
	o.SetSequenced(true)
	for i := 0; i < b.N; i++ {
		if err := o.Send(p); err != nil {
			b.Error(err.Error())
			return
		}
	}
	o.Close()
}

func BenchmarkTimedBufferedOutput(b *testing.B) {
	var w nullwriter
	p, err := nmsg.Payload(testMessage(1000))
	if err != nil {
		b.Error(err.Error())
	}
	o := nmsg.TimedBufferedOutput(w, 100*time.Millisecond)
	o.SetMaxSize(1500, 0)
	o.SetSequenced(true)
	for i := 0; i < b.N; i++ {
		if err := o.Send(p); err != nil {
			b.Error(err.Error())
			return
		}
	}
	o.Close()
}

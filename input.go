/*
 * Copyright (c) 2017,2018 by Farsight Security, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package nmsg

import (
	"bufio"
	"fmt"
	"io"
	"time"
)

// An Input is a source of NMSG Payloads.
type Input interface {
	// Recv() returns the next Nmsg Payload from the input,
	// blocking if none is available.
	Recv() (*NmsgPayload, error)
	// Stats() returns interface statistics
	Stats() *InputStatistics
}

// InputStatistics holds useful metrics for input performance.
type InputStatistics struct {
	// Count of total container received, including fragments
	InputContainers uint64
	// Count of total bytes received and processed
	InputBytes uint64
	// Count of containers marked lost by sequence tracking
	LostContainers uint64
	// Count of fragment containers received
	InputFragments uint64
	// Count of fragments expired from cache
	ExpiredFragments uint64
	// Count of containers dropped due to incomplete fragments
	PartialContainers uint64
}

type dataError struct{ error }

func (d *dataError) Error() string { return d.error.Error() }

// IsDataError returns true of the supplied error is an error unpacking
// or decoding the NMSG data rather than an I/O error with the input.
func IsDataError(err error) bool {
	_, ok := err.(*dataError)
	return ok
}

type input struct {
	r      io.Reader
	n      Nmsg
	fcache *fragCache
	scache *seqCache
	stats  InputStatistics
}

func (i *input) Stats() *InputStatistics {
	res := &InputStatistics{}
	*res = i.stats
	return res
}

// NewInput constructs an input from the supplied Reader.
// The size parameter sizes the input buffer, and should
// be greater than the maximum anticipated container size
// for datagram inputs.
func NewInput(r io.Reader, size int) Input {
	return &input{
		r:      bufio.NewReaderSize(r, size),
		n:      Nmsg{},
		fcache: newFragmentCache(2 * time.Minute),
		scache: newSequenceCache(2 * time.Minute),
	}
}

type checksumError struct {
	calc, wire uint32
}

func (c *checksumError) Error() string {
	return fmt.Sprintf("checksum mismatch: %x != %x", c.calc, c.wire)
}

func (i *input) Recv() (*NmsgPayload, error) {
	for len(i.n.Payloads) == 0 {
		var c Container
		n, err := c.ReadFrom(i.r)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, io.EOF
		}

		i.stats.InputBytes += uint64(n)

		if c.NmsgFragment != nil {
			i.stats.InputFragments++
			var b []byte
			if b = i.fcache.Insert(c.NmsgFragment); b == nil {
				continue
			}
			err = c.fromNmsgBytes(b, c.isCompressed, false)
			if err != nil {
				return nil, &dataError{err}
			}
		}

		i.stats.InputContainers++
		i.stats.LostContainers += uint64(i.scache.Update(&c.Nmsg))
		i.scache.Expire()
		i.n = c.Nmsg
	}
	ccount, fcount := i.fcache.Expire()
	i.stats.PartialContainers += uint64(ccount)
	i.stats.ExpiredFragments += uint64(fcount)
	p := i.n.Payloads[0]
	i.n.Payloads = i.n.Payloads[1:]

	var err error
	if len(i.n.PayloadCrcs) > 0 {
		wire := i.n.PayloadCrcs[0]
		calc := nmsgCRC(p.Payload)
		if wire != calc {
			err = &dataError{&checksumError{calc, wire}}
		}
		i.n.PayloadCrcs = i.n.PayloadCrcs[1:]
	}

	return p, err
}

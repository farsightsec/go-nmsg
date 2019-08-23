/*
 * Copyright (c) 2017 by Farsight Security, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package nmsg

/*
#cgo pkg-config: libnmsg
#cgo LDFLAGS: -lnmsg
#include <stdlib.h>
#include <nmsg.h>

extern void outputCallback(nmsg_message_t, void *);

void output_callback(nmsg_message_t msg, void *user) {
        outputCallback(msg, user);
}
*/
import "C"
import (
	"io"
	"net"
	"os"
	"unsafe"
)

// An Output is a destination for NMSG data (Messages)
type Output interface {
	// Write sends the supplied message to the Output.
	Write(*Message) error

	// SetBuffered controls whether the output buffers Messages into containers
	// before sending them. NmsgOutputs are buffered by default, but low volume
	// sources may choose to turn this off to reduce latency.
	SetBuffered(bool)

	// SetCompression controls whether the output compresses
	// the container data prior to sending.
	SetCompression(bool)

	// Flush writes any buffered data to the Output.
	Flush() error

	// SetFilterMsgtype instructs the output to discard all Messages
	// not of the supplied vendor and type, specified by number.
	SetFilterMsgtype(vendor, msgtype uint32)

	// SetFilterMsgtypeByname instructs the output to discard all Messages
	// not of the supplied vendor and type, specified by name.
	SetFilterMsgtypeByname(vendor, msgtype string)

	// SetRate sets an output rate limit. The rate is specified
	// in containers per second, and is checked every freq pauses.
	// The freq parameter should be about 10-15% of the rate.
	SetRate(rate *Rate)

	// SetSource instructs the output to set the source parameter
	// of all outbound messages to the supplied value.
	SetSource(source uint32)

	// SetOperator instructs the output to set the operator parameter
	// of all outbound messages to the supplied value.
	SetOperator(group uint32)

	// SetGroup instructs the output to set the group parameter
	// of all outbound messages to the supplied value.
	SetGroup(group uint32)
}

// An NmsgOutput is an output managed by the nmsg library.
type nmsgOutput struct {
	file   *os.File
	rate   *Rate
	output C.nmsg_output_t
}

func (o *nmsgOutput) Write(m *Message) error {
	return nmsgError(C.nmsg_output_write(o.output, m.message))
}

func (o *nmsgOutput) SetBuffered(buffered bool) {
	C.nmsg_output_set_buffered(o.output, C.bool(buffered))
}

func (o *nmsgOutput) SetFilterMsgtype(vid, msgtype uint32) {
	C.nmsg_output_set_filter_msgtype(o.output, C.uint(vid), C.uint(msgtype))
}

func (o *nmsgOutput) SetFilterMsgtypeByname(vendor, msgtype string) {
	cname := C.CString(vendor)
	ctype := C.CString(msgtype)
	C.nmsg_output_set_filter_msgtype_byname(o.output, cname, ctype)
	C.free(unsafe.Pointer(cname))
	C.free(unsafe.Pointer(ctype))
}

func (o *nmsgOutput) SetRate(r *Rate) {
	if r == nil {
		C.nmsg_output_set_rate(o.output, nil)
	} else {
		C.nmsg_output_set_rate(o.output, r.rate)
	}
	// keep a reference to avoid calling the finalizer
	o.rate = r
}

func (o *nmsgOutput) SetSource(source uint32) {
	C.nmsg_output_set_source(o.output, C.uint(source))
}

func (o *nmsgOutput) SetOperator(operator uint32) {
	C.nmsg_output_set_operator(o.output, C.uint(operator))
}

func (o *nmsgOutput) SetGroup(group uint32) {
	C.nmsg_output_set_group(o.output, C.uint(group))
}

func (o *nmsgOutput) SetCompression(compress bool) {
	C.nmsg_output_set_zlibout(o.output, C.bool(compress))
}

func (o *nmsgOutput) Flush() error {
	return nmsgError(C.nmsg_output_flush(o.output))
}

// NewOutput creates an output writing to w, with target
// container size of bufsiz. The Writer currently must be a
// *os.File or *net.UDPConn.
func NewOutput(w io.Writer, bufsiz int) Output {
	switch w := w.(type) {
	case *net.UDPConn:
		f, err := w.File()
		if err != nil {
			return nil
		}
		return &nmsgOutput{f, nil, C.nmsg_output_open_sock(C.int(f.Fd()), C.size_t(bufsiz))}
	case *os.File:
		return &nmsgOutput{w, nil, C.nmsg_output_open_file(C.int(w.Fd()), C.size_t(bufsiz))}
	default:
		return newContainerOutput(w, bufsiz)
	}
}

// NewCallbackOutput creates an NmsgOutput which calls o.Send()
// on every message.
func NewCallbackOutput(o OutputFunc) Output {
	return &nmsgOutput{
		file:   nil,
		output: C.nmsg_output_open_callback(C.nmsg_cb_message(C.output_callback), registerOutput(o)),
	}
}

// An OutputFunc is a function with the same signature as Output.Write, usable
// directly as an Output.
//
// When used directly as an Output, only the Write() method is defined. All others
// are no-ops.
type OutputFunc func(*Message) error

// Write calls the underlying function with the supplied message
func (o OutputFunc) Write(m *Message) error { return o(m) }

// Flush satisfies the Output interface with a no-op
func (o OutputFunc) Flush() error { return nil }

// SetBuffered satisfies the Output interface with a no-op
func (o OutputFunc) SetBuffered(bool) {}

// SetCompression satisfies the Output interface with a no-op
func (o OutputFunc) SetCompression(bool) {}

// SetFilterMsgtype satisfies the Output interface with a no-op
func (o OutputFunc) SetFilterMsgtype(vendor, msgtype uint32) {}

// SetFilterMsgtypeByname satisfies the Output interface with a no-op
func (o OutputFunc) SetFilterMsgtypeByname(vendor, msgtype string) {}

// SetRate satisfies the Output interface with a no-op
func (o OutputFunc) SetRate(r *Rate) {}

// SetSource satisfies the Output interface with a no-op
func (o OutputFunc) SetSource(source uint32) {}

// SetOperator satisfies the Output interface with a no-op
func (o OutputFunc) SetOperator(group uint32) {}

// SetGroup satisfies the Output interface with a no-op
func (o OutputFunc) SetGroup(group uint32) {}

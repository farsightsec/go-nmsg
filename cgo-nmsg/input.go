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

extern nmsg_res inputCallback(nmsg_message_t *msg, void *user);

nmsg_res input_callback(nmsg_message_t *msg, void *user) {
        return inputCallback(msg, user);
}
*/
import "C"
import (
	"io"
	"net"
	"os"
	"unsafe"
)

// An Input is a source of NMSG payloads (Messages).
type Input interface {
	// Read returns a Message or nil, and an error if any.
	Read() (*Message, error)

	// SetFilterMsgtype instructs the input to discard all Messages
	// not of the given vendor id and msgtype, specified by number.
	SetFilterMsgtype(vendor, msgtype uint32)

	// SetFilterMsgtypeByname instructs the input to discard all Messages
	// not of the given vendor id and msgtype, specified by name.
	SetFilterMsgtypeByname(vendor, msgtype string)

	// SetFilterSource instructs the input to discard all Messages not
	// from the supplied source.
	SetFilterSource(source uint32)

	// SetFilterOperator instructs the input to discard all Messages not
	// from the supplied operator.
	SetFilterOperator(operator uint32)

	// SetFilterGroup instructs the input to discard all Messages not
	// in the supplied group.
	SetFilterGroup(group uint32)
}

// NmsgInput is an Input managed by libnmsg. It satisfies
// the Input interface, and has
type nmsgInput struct {
	file  *os.File
	input C.nmsg_input_t
}

func (i *nmsgInput) Read() (*Message, error) {
	var msg C.nmsg_message_t
	res := C.nmsg_input_read(i.input, &msg)
	if res == C.nmsg_res_success {
		return messageFromC(msg), nil
	}
	return nil, nmsgError(res)
}

func (i *nmsgInput) SetFilterMsgtype(vid, msgtype uint32) {
	C.nmsg_input_set_filter_msgtype(i.input, C.uint(vid), C.uint(msgtype))
}

func (i *nmsgInput) SetFilterMsgtypeByname(vendor, msgtype string) {
	cname := C.CString(vendor)
	ctype := C.CString(msgtype)
	C.nmsg_input_set_filter_msgtype_byname(i.input, cname, ctype)
	C.free(unsafe.Pointer(cname))
	C.free(unsafe.Pointer(ctype))
}

func (i *nmsgInput) SetFilterSource(source uint32) {
	C.nmsg_input_set_filter_source(i.input, C.uint(source))
}

func (i *nmsgInput) SetFilterOperator(operator uint32) {
	C.nmsg_input_set_filter_operator(i.input, C.uint(operator))
}

func (i *nmsgInput) SetFilterGroup(group uint32) {
	C.nmsg_input_set_filter_group(i.input, C.uint(group))
}

// NewInput creates a new Input from an io.Reader.
// Currently, the reader must be a *net.UDPConn or a *os.File
func NewInput(r io.Reader) Input {
	switch r := r.(type) {
	case *net.UDPConn:
		f, err := r.File()
		if err != nil {
			return nil
		}
		return &nmsgInput{f, C.nmsg_input_open_sock(C.int(f.Fd()))}
	case *os.File:
		return &nmsgInput{r, C.nmsg_input_open_file(C.int(r.Fd()))}
	default:
		return nil
		// return &containerReader{Reader: r}
	}
}

// NewCallbackInput creates an NmsgInput which calls the supplied InputFunc.
func NewCallbackInput(i InputFunc) Input {
	return &nmsgInput{
		file:  nil,
		input: C.nmsg_input_open_callback(C.nmsg_cb_message_read(C.input_callback), registerInput(i)),
	}
}

// An InputFunc is a function with the same signature as Input.Read(), usable
// directly as an Input.
//
// When used directly as an Input, only the Read() method is implemented. All
// others are no-ops. If the functionality of the other methods is desired,
// the InputFunc can be passed to NewCallbackInput.
type InputFunc func() (*Message, error)

// Read calls the underlying function to return the next message.
func (i InputFunc) Read() (*Message, error) { return i() }

// SetFilterMsgtype satisfies the Input interface with a no-op
func (i InputFunc) SetFilterMsgtype(vendor, msgtype uint32) {}

// SetFilterMsgtypeByname satisfies the Input interface with a no-op
func (i InputFunc) SetFilterMsgtypeByname(vendor, msgtype string) {}

// SetFilterSource satisfies the Input interface with a no-op
func (i InputFunc) SetFilterSource(source uint32) {}

// SetFilterOperator satisfies the Input interface with a no-op
func (i InputFunc) SetFilterOperator(operator uint32) {}

// SetFilterGroup satisfies the Input interface with a no-op
func (i InputFunc) SetFilterGroup(group uint32) {}

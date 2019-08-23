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
*/
import "C"
import "unsafe"

// IO is a handle to a libnmsg io loop connecting one or more Inputs
// with one ore more Outputs.
type IO struct {
	nmsgIO C.nmsg_io_t
}

// NewIO creates and returns a new IO
func NewIO() *IO {
	io := C.nmsg_io_init()
	if io != nil {
		return &IO{io}
	}
	return nil
}

// AddInputChannel opens an NMSG channel and adds it as an Input to the
// IO.
func (io *IO) AddInputChannel(channel string) error {
	cchan := C.CString(channel)
	res := C.nmsg_io_add_input_channel(io.nmsgIO, cchan, nil)
	C.free(unsafe.Pointer(cchan))
	return nmsgError(res)
}

// AddInputSockSpec opens one or more sockets based on the sockspec
// (add/port ,or addr/lowport..highport) and adds it to the IO
// as an input.
func (io *IO) AddInputSockSpec(sockspec string) error {
	css := C.CString(sockspec)
	res := C.nmsg_io_add_input_sockspec(io.nmsgIO, css, nil)
	C.free(unsafe.Pointer(css))
	return nmsgError(res)
}

// AddInput adds a separately created Input to the IO as an input.
func (io *IO) AddInput(i Input) error {
	ni, ok := i.(*nmsgInput)
	if !ok {
		ni = NewCallbackInput(i.Read).(*nmsgInput)
	}
	return nmsgError(C.nmsg_io_add_input(io.nmsgIO, ni.input, nil))
}

// AddOutput adds a separately created Output to the IO as an output.
func (io *IO) AddOutput(o Output) error {
	nout, ok := o.(*nmsgOutput)
	if !ok {
		nout = NewCallbackOutput(o.Write).(*nmsgOutput)
	}
	return nmsgError(C.nmsg_io_add_output(io.nmsgIO, nout.output, nil))
}

// SetMirrored controls whether the IO mirrors output to all outputs
// (mirrored = true) or stripes its output across all outputs.
func (io *IO) SetMirrored(mirrored bool) {
	if mirrored {
		C.nmsg_io_set_output_mode(io.nmsgIO, C.nmsg_io_output_mode_mirror)
		return
	}
	C.nmsg_io_set_output_mode(io.nmsgIO, C.nmsg_io_output_mode_stripe)
}

// SetDebug sets the debug print level of the underlying io.
// Larger numbers are more verbose.
func (io *IO) SetDebug(debug int) {
	C.nmsg_io_set_debug(io.nmsgIO, C.int(debug))
}

// Run starts the IO loop, returning when it is finished or broken
// with Break()
func (io *IO) Run() error {
	return nmsgError(C.nmsg_io_loop(io.nmsgIO))
}

// Break stops the IO main loop.
func (io *IO) Break() {
	C.nmsg_io_breakloop(io.nmsgIO)
}

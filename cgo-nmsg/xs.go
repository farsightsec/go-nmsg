// +build libxs

/*
 * Copyright (c) 2017 by Farsight Security, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package nmsg

/*
#cgo pkg-config: libnmsg libxs
#cgo LDFLAGS: -lnmsg -lxs
#include <stdlib.h>
#include <nmsg.h>
#include <xs/xs.h>
*/
import "C"
import "unsafe"

var xsContext unsafe.Pointer

func init() {
	xsContext = C.xs_init()
}

// NewXSInput opens an Input reading from the given XS endpoint.
func NewXSInput(xep string) Input {
	cxep := C.CString(xep)
	defer C.free(unsafe.Pointer(cxep))
	inp := C.nmsg_input_open_xs_endpoint(xsContext, cxep)
	if inp == nil {
		return nil
	}
	return &nmsgInput{input: inp}
}

// NewXSOutput creates an output writing to the given XS endpoint.
func NewXSOutput(xep string, bufsiz int) Output {
	cxep := C.CString(xep)
	defer C.free(unsafe.Pointer(cxep))
	outp := C.nmsg_output_open_xs_endpoint(xsContext, cxep, C.size_t(bufsiz))
	if outp == nil {
		return nil
	}
	return &nmsgOutput{output: outp}
}

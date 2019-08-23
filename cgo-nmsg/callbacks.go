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
#include <nmsg.h>
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"runtime"
	"sync"
	"unsafe"
)

type outCbEntry struct {
	index int
	Output
}

type inCbEntry struct {
	index int
	Input
}

var cbm sync.Mutex
var outCbTable []Output
var inCbTable []Input

// The C library may not hold a pointer to a Go variable, but we
// need to store enough context in the callback user data to find
// the go object which registered the callback. We solve this by
// allocating memory on the C side (with C.malloc, C.calloc) and
// storing a value in that memory which we can use to look up the
// Go value on the Go side.
//
// The approach we take here is to have a package-global list of
// Output and Input, and store the index in the list as a C.int
// in C-allocated memory. The location of this memory is returned
// as an unsafe.Pointer suitable for passing to the (void *user)
// argument of libnmsg callback registration functions.

func registerOutput(o Output) unsafe.Pointer {
	cbm.Lock()
	defer cbm.Unlock()
	idx := len(outCbTable)
	outCbTable = append(outCbTable, o)
	idxptr := C.calloc(C.size_t(1), C.size_t(unsafe.Sizeof(C.int(1))))
	*(*C.int)(idxptr) = C.int(idx)
	return idxptr
}

func registerInput(i Input) unsafe.Pointer {
	cbm.Lock()
	defer cbm.Unlock()
	idx := len(inCbTable)
	inCbTable = append(inCbTable, i)
	idxptr := C.calloc(C.size_t(1), C.size_t(unsafe.Sizeof(C.int(1))))
	*(*C.int)(idxptr) = C.int(idx)
	return idxptr
}

//export outputCallback
func outputCallback(msg C.nmsg_message_t, user unsafe.Pointer) {
	idx := int(*(*C.int)(user))
	if idx < len(outCbTable) {
		o := outCbTable[idx]
		o.Write(messageFromC(msg))
		return
	}
	panic(fmt.Sprintf("outputCallback: invalid index %d", idx))
}

//export inputCallback
func inputCallback(msg, user unsafe.Pointer) C.nmsg_res {
	idx := int(*(*C.int)(user))
	if idx < len(inCbTable) {
		i := inCbTable[idx]
		for {
			m, err := i.Read()

			if ErrorRetry(err) {
				continue
			}
			if err != nil {
				*(*C.nmsg_message_t)(msg) = nil
				if e, ok := err.(nmsgResError); ok {
					return C.nmsg_res(e)
				}
				return C.nmsg_res_failure
			}
			runtime.SetFinalizer(m, nil)
			*(*C.nmsg_message_t)(msg) = m.message
			return C.nmsg_res_success
		}
	}
	panic(fmt.Sprintf("inputCallback: invalid index %d", idx))
}

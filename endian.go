/*
 * Copyright (c) 2017 by Farsight Security, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package nmsg

// The nmsg C library renders checksums in network byte order before presenting
// them to the protobuf-c library as uint32 values. While Go's encoding/binary
// library can format and parse uint32 values as BigEndian or LittleEndian byte
// arrays, this is not sufficient to calculate an integer that will represent
// a BigEndian (network) byte array in the host's native byte order. This
// requires determining the host's byte order, a task which Go's type system
// makes cumbersome.
//
// This file uses the "unsafe" package to defeat Go's type system for the
// purposes of determining whether the package is running on a BigEndian or
// LittleEndian machine, and uses this information to implement htonl.

import (
	"encoding/binary"
	"unsafe"
)

var hostEndian binary.ByteOrder

func init() {
	n := uint32(1)
	b := *(*[4]byte)(unsafe.Pointer(&n))
	if b[0] == 1 {
		hostEndian = binary.LittleEndian
	} else {
		hostEndian = binary.BigEndian
	}
}

func htonl(n uint32) uint32 {
	var buf [4]byte
	hostEndian.PutUint32(buf[:], n)
	return binary.BigEndian.Uint32(buf[:])
}

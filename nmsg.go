/*
 * Copyright (c) 2017 by Farsight Security, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

//go:generate protoc --go_out=. nmsg.proto

package nmsg

import (
	"hash/crc32"

	"google.golang.org/protobuf/proto"
)

// Container size limits to avoid silly fragmentation and memory
// exhaustion.
const (
	MinContainerSize     = 512
	MaxContainerSize     = 1048576
	EtherContainerSize   = 1280
	invalidContainerSize = MaxContainerSize * 16
)

var crc32c = crc32.MakeTable(crc32.Castagnoli)

// nmsgCRC calculates a crc32 checksum compatible with that used by
// the nmsg C library.
//
// As in the C library, the checksum is converted to network byte order
// before eventually being encoded as a protocol buffers integer. This
// defeats the endian neutrality of protocol buffers, but is necessary
// for compatibility with the C library operating on little endian machines.
func nmsgCRC(b []byte) uint32 {
	return htonl(crc32.Checksum(b, crc32c))
}

// Message encapsulates a protobuf-encoded payload.
//
// The values returned by the GetVid() and GetMsgtype() methods return
// identify the format of the payload.
type Message interface {
	proto.Message
	GetVid() uint32
	GetMsgtype() uint32
}

/*
 * Copyright (c) 2017 by Farsight Security, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package nmsg

import (
	"fmt"
	"reflect"
)

var types map[uint32]map[uint32]reflect.Type

// Register records the supplied message's type, indexed by its MessageType
// and VendorID, for the purposes of decoding protobuf-encoded payloads.
//
// Register should be called from the init() function of the module defining
// the payload type. It is not safe to call from multiple goroutines, and
// may not be called if any goroutine is concurrently decoding NMSG payloads.
func Register(m Message) {
	if types == nil {
		types = make(map[uint32]map[uint32]reflect.Type)
	}
	vid := m.GetVid()
	v, ok := types[vid]
	if !ok {
		v = make(map[uint32]reflect.Type)
		types[vid] = v
	}

	msgtype := m.GetMsgtype()
	v[msgtype] = reflect.TypeOf(m)
}

type unknownVendor uint32

func (v unknownVendor) Error() string {
	return fmt.Sprintf("Vendor %d has no registered Msgtypes.", v)
}

type unknownMsgtype struct{ vid, msgtype uint32 }

func (t unknownMsgtype) Error() string {
	return fmt.Sprintf("Msgtype %d is not registered for vendor %d.", t.msgtype, t.vid)
}

// NewMessage creates a new Message with an underlying type identified
// by vid, msgtype.
func NewMessage(vid, msgtype uint32) (Message, error) {
	v, ok := types[vid]
	if !ok {
		return nil, unknownVendor(vid)
	}

	t, ok := v[msgtype]
	if !ok {
		return nil, unknownMsgtype{vid, msgtype}
	}

	return reflect.New(t.Elem()).Interface().(Message), nil
}

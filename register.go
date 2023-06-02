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
	"strings"
)

var types map[uint32]map[uint32]reflect.Type
var typesByName map[uint32]map[string]uint32

var vendors map[uint32]string
var vids map[string]uint32

// Register records the supplied message's type, indexed by its MessageType
// and VendorID, for the purposes of decoding protobuf-encoded payloads.
//
// Register should be called from the init() function of the module defining
// the payload type. It is not safe to call from multiple goroutines, and
// may not be called if any goroutine is concurrently decoding NMSG payloads.
func Register(m Message) {
	if types == nil {
		types = make(map[uint32]map[uint32]reflect.Type)
		typesByName = make(map[uint32]map[string]uint32)
	}
	vid := m.GetVid()
	v, ok := types[vid]
	if !ok {
		v = make(map[uint32]reflect.Type)
		types[vid] = v
	}

	msgtype := m.GetMsgtype()
	v[msgtype] = reflect.TypeOf(m)

	name := strings.ToLower(v[msgtype].Elem().Name())

	tn, ok := typesByName[vid]
	if !ok {
		tn = make(map[string]uint32)
		typesByName[vid] = tn
	}

	tn[name] = msgtype
}

// RegisterVendor records an association between the vendor named `vname`
// and a numeric vendor id `vid`
func RegisterVendor(vname string, vid uint32) {
	if vendors == nil {
		vendors = make(map[uint32]string)
		vids = make(map[string]uint32)
	}
	vendors[vid] = vname
	vids[vname] = vid
}

type unknownVid uint32

func (v unknownVid) Error() string {
	return fmt.Sprintf("Vendor %d not registered.", v)
}

type unknownVendor string

func (v unknownVendor) Error() string {
	return fmt.Sprintf("Vendor '%s' not registered.", string(v))
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
		return nil, unknownVid(vid)
	}

	t, ok := v[msgtype]
	if !ok {
		return nil, unknownMsgtype{vid, msgtype}
	}

	return reflect.New(t.Elem()).Interface().(Message), nil
}

// VendorByname returns the numeric vendor id registered for the given
// name, if any.
func VendorByName(vname string) (uint32, error) {
	vid, ok := vids[vname]
	if !ok {
		return 0, unknownVendor(vname)
	}
	return vid, nil
}

// VendorName returns the vendor name registered for the given
// numeric vid, if any.
func VendorName(vid uint32) (string, error) {
	vname, ok := vendors[vid]
	if !ok {
		return "", unknownVid(vid)
	}
	return vname, nil
}

// MessageTypeByName returns the numeric vendor id and message type
// for the given vendor name and message type name, for the purposes
// of creating a new message with NewMessage().
func MessageTypeByName(vname string, mname string) (vid uint32, mtype uint32, err error) {
	var ok bool

	vid, err = VendorByName(vname)
	if err != nil {
		return
	}

	mtype, ok = typesByName[vid][strings.ToLower(mname)]
	if !ok {
		err = fmt.Errorf("Unknown message type '%s' for vendor '%s'", mname, vname)
	}
	return
}

// MessageTypeName returns a vendor and message type name for a given
// numeric vendor id and message type, if any
func MessageTypeName(vid uint32, msgtype uint32) (vname string, mname string, err error) {
	var ok bool
	vname, err = VendorName(vid)
	if err != nil {
		return
	}

	v, ok := types[vid]
	if !ok {
		err = unknownVid(vid)
		return
	}

	t, ok := v[msgtype]
	if !ok {
		err = unknownMsgtype{vid, msgtype}
		return
	}

	mname = strings.ToLower(t.Elem().Name())
	return
}

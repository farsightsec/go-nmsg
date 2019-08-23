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

const char *endline="\n";
unsigned flag_repeated = NMSG_MSGMOD_FIELD_REPEATED;
*/
import "C"
import (
	"fmt"
	"net"
	"runtime"
	"unsafe"
)

// MessageMod something something
type MessageMod struct {
	nmsgMsgMod C.nmsg_msgmod_t
}

// MessageModLookupByName something something
func MessageModLookupByName(vname, mname string) *MessageMod {
	vstr := C.CString(vname)
	mstr := C.CString(mname)
	defer C.free(unsafe.Pointer(vstr))
	defer C.free(unsafe.Pointer(mstr))
	return &MessageMod{C.nmsg_msgmod_lookup_byname(vstr, mstr)}
}

// MessageModLookup something something
func MessageModLookup(v, m uint32) *MessageMod {
	return &MessageMod{C.nmsg_msgmod_lookup(C.uint(v), C.uint(m))}
}

// A Message is a unit of NMSG data.
type Message struct {
	message C.nmsg_message_t
}

// NewMessage initializes a message of a type given by
// the supplied MessageMod
func NewMessage(mod *MessageMod) *Message {
	return messageFromC(C.nmsg_message_init(mod.nmsgMsgMod))
}

// NewMessageFromPayload encapsulates a byte buffer in a payload with
// the supplied vendor and message type.
func NewMessageFromPayload(payload []byte, vendor uint32, msgtype uint32) *Message {
	Csiz := C.size_t(len(payload))
	// C.CString allocates a buffer to hold the copy of payload
	// built by string. This buffer is passed to nmsg_message_from_raw_payload,
	// which takes ownership of the buffer. It will be freed when
	// nmsg_message_destroy() is called by the Message finalizer.
	Cbuf := unsafe.Pointer(C.CString(string(payload)))
	return messageFromC(C.nmsg_message_from_raw_payload(
		C.unsigned(vendor), C.unsigned(msgtype),
		(*C.uint8_t)(Cbuf), Csiz, nil))
}

func messageDestroy(m *Message) {
	C.nmsg_message_destroy(&m.message)
}

// GetMsgtype returns the vendor and payload type of the message.
func (msg *Message) GetMsgtype() (vendor, msgtype uint32) {
	vendor = uint32(C.nmsg_message_get_vid(msg.message))
	msgtype = uint32(C.nmsg_message_get_msgtype(msg.message))
	return
}

// Source returns the source id of the message, or zero if the source id
// is not set.
func (msg *Message) Source() uint32 {
	return uint32(C.nmsg_message_get_source(msg.message))
}

// SetSource sets the source id of the message.
func (msg *Message) SetSource(source uint32) {
	C.nmsg_message_set_source(msg.message, C.uint32_t(source))
}

// Operator returns the operator id of the message, or zero if the operator id
// is not set.
func (msg *Message) Operator() uint32 {
	return uint32(C.nmsg_message_get_operator(msg.message))
}

// SetOperator sets the operator id of the message.
func (msg *Message) SetOperator(operator uint32) {
	C.nmsg_message_set_operator(msg.message, C.uint32_t(operator))
}

// Group returns the group id of the message, or zero if the group id
// is not set.
func (msg *Message) Group() uint32 {
	return uint32(C.nmsg_message_get_group(msg.message))
}

// SetGroup sets the group id of the message.
func (msg *Message) SetGroup(group uint32) {
	C.nmsg_message_set_group(msg.message, C.uint32_t(group))
}

func messageFromC(message C.nmsg_message_t) *Message {
	msg := &Message{message}
	runtime.SetFinalizer(msg, messageDestroy)
	return msg
}

// MarshalJSON formats a JSON representation of the Message
func (msg *Message) MarshalJSON() ([]byte, error) {
	var jsonCstr *C.char
	err := nmsgError(C.nmsg_message_to_json(msg.message, &jsonCstr))
	defer C.free(unsafe.Pointer(jsonCstr))
	if err != nil {
		return nil, err
	}
	return []byte(C.GoString(jsonCstr)), nil
}

// UnmarshalJSON parses a JSON representation of the Message
func (msg *Message) UnmarshalJSON(b []byte) error {
	jsonCstr := C.CString(string(b))
	defer C.free(unsafe.Pointer(jsonCstr))
	return nmsgError(C.nmsg_message_from_json(jsonCstr, &msg.message))
}

// MarshalText converts a Message to presentation format.
func (msg *Message) MarshalText() ([]byte, error) {
	var presCstr *C.char
	err := nmsgError(C.nmsg_message_to_pres(msg.message, &presCstr, C.endline))
	defer C.free(unsafe.Pointer(presCstr))
	if err != nil {
		return nil, err
	}
	return []byte(C.GoString(presCstr)), nil
}

// Enum contains both the numeric Value and the string Description of
// an enumerated NMSG field value.
type Enum struct {
	Value       uint32
	Description string
}

type fieldValue struct {
	typ  C.nmsg_msgmod_field_type
	buf  unsafe.Pointer
	size C.int
}

func (msg *Message) getFieldValue(name string, idx int) (fv fieldValue, err error) {
	var Csize C.size_t

	Cname := C.CString(name)
	defer C.free(unsafe.Pointer(Cname))

	Cidx := C.uint(uint(idx))

	res := C.nmsg_message_get_field_type(msg.message, Cname, &fv.typ)
	if err = nmsgError(res); err != nil {
		return
	}

	res = C.nmsg_message_get_field(msg.message, Cname, Cidx, &fv.buf, &Csize)
	if err = nmsgError(res); err != nil {
		return
	}

	fv.size = C.int(Csize)
	return
}

func (msg *Message) setFieldValue(name string, idx int, buf unsafe.Pointer, size int) error {
	Cname := C.CString(name)
	defer C.free(unsafe.Pointer(Cname))

	Cidx := C.uint(uint(idx))
	Csize := C.size_t(size)
	return nmsgError(C.nmsg_message_set_field(msg.message, Cname, Cidx,
		(*C.uint8_t)(buf), Csize))
}

// GetUintField retrieves the named field of a unsigned int type from a Message.
// If the field has an enumerated type, the numeric value is retrieved.
func (msg *Message) GetUintField(name string, idx int) (uint64, error) {
	fv, err := msg.getFieldValue(name, idx)
	if err != nil {
		return 0, err
	}

	switch fv.typ {
	case C.nmsg_msgmod_ft_uint16:
		return uint64(*(*uint16)(fv.buf)), nil
	case C.nmsg_msgmod_ft_uint32:
		fallthrough
	case C.nmsg_msgmod_ft_enum:
		return uint64(*(*uint32)(fv.buf)), nil
	case C.nmsg_msgmod_ft_uint64:
		return *(*uint64)(fv.buf), nil
	default:
		return 0, fmt.Errorf("Field %s not of uint type", name)
	}

}

// SetUintField sets the value of a field of type uint16, uint32, or uint64.
// The bitsize parameter specifies which type, and must be 16, 32, or 64
func (msg *Message) SetUintField(name string, idx, bitsize int, val uint64) error {
	switch bitsize {
	case 16:
		v := uint16(val)
		return msg.setFieldValue(name, idx, unsafe.Pointer(&v), bitsize)
	case 32:
		v := uint32(val)
		return msg.setFieldValue(name, idx, unsafe.Pointer(&v), bitsize)
	case 64:
		v := uint64(val)
		return msg.setFieldValue(name, idx, unsafe.Pointer(&v), bitsize)
	default:
		return fmt.Errorf("Invalid bitsize %d", bitsize)
	}
}

// GetIntField retrieves the value of a named field of integer type from
// a Message.
func (msg *Message) GetIntField(name string, idx int) (int64, error) {
	fv, err := msg.getFieldValue(name, idx)
	if err != nil {
		return 0, err
	}

	switch fv.typ {
	case C.nmsg_msgmod_ft_int16:
		return int64(*(*int16)(fv.buf)), nil
	case C.nmsg_msgmod_ft_int32:
		return int64(*(*int32)(fv.buf)), nil
	case C.nmsg_msgmod_ft_int64:
		return *(*int64)(fv.buf), nil
	default:
		return 0, fmt.Errorf("Field %s not of int type", name)
	}
}

// SetIntField sets the value of an int16, int32, or int64 field in the message.
// The bitsize field specifies which size, and must by 16, 32, or 64
func (msg *Message) SetIntField(name string, idx, bitsize int, val int64) error {
	switch bitsize {
	case 16:
		v := int16(val)
		return msg.setFieldValue(name, idx, unsafe.Pointer(&v), bitsize)
	case 32:
		v := int32(val)
		return msg.setFieldValue(name, idx, unsafe.Pointer(&v), bitsize)
	case 64:
		v := int64(val)
		return msg.setFieldValue(name, idx, unsafe.Pointer(&v), bitsize)
	default:
		return fmt.Errorf("Invalid bitsize %d", bitsize)
	}
}

// GetBytesField retrieves a field of type bytes from a Message.
func (msg *Message) GetBytesField(name string, idx int) ([]byte, error) {
	fv, err := msg.getFieldValue(name, idx)
	if err != nil {
		return nil, err
	}
	if fv.typ != C.nmsg_msgmod_ft_bytes {
		return nil, fmt.Errorf("Field %s not of bytes type", name)
	}
	return C.GoBytes(fv.buf, fv.size), nil
}

// SetBytesField sets the value of a bytes field in a Message
func (msg *Message) SetBytesField(name string, idx int, val []byte) error {
	Cbuf := unsafe.Pointer(&val[0])
	return msg.setFieldValue(name, idx, Cbuf, len(val))
}

// GetStringField retrieves the value of a string field in a Message
func (msg *Message) GetStringField(name string, idx int) (string, error) {
	fv, err := msg.getFieldValue(name, idx)
	if err != nil {
		return "", err
	}
	return C.GoStringN((*C.char)(fv.buf), fv.size), nil
}

// SetStringField sets the value of a string field in a Message
func (msg *Message) SetStringField(name string, idx int, val string) error {
	b := []byte(val)
	Cbuf := unsafe.Pointer(&b[0])
	return msg.setFieldValue(name, idx, Cbuf, len(val))
}

// GetIPField retrieves the value of an IP field in a Message
func (msg *Message) GetIPField(name string, idx int) (net.IP, error) {
	fv, err := msg.getFieldValue(name, idx)
	if err != nil {
		return nil, err
	}
	if fv.typ != C.nmsg_msgmod_ft_ip {
		return nil, fmt.Errorf("Field %s not of iptype", name)
	}
	return net.IP(C.GoBytes(fv.buf, fv.size)), nil
}

// SetIPField sets the value of an IP field in a Message
func (msg *Message) SetIPField(name string, idx int, val net.IP) error {
	Cbuf := unsafe.Pointer(&val[0])
	return msg.setFieldValue(name, idx, Cbuf, len(val))
}

// GetDoubleField retrieves the value of a double field in a Message
func (msg *Message) GetDoubleField(name string, idx int) (float64, error) {
	fv, err := msg.getFieldValue(name, idx)
	if err != nil {
		return 0, err
	}
	if fv.typ != C.nmsg_msgmod_ft_double {
		return 0, fmt.Errorf("Field %s is not of double type", name)
	}
	return *(*float64)(fv.buf), nil
}

// SetDoubleField sets the value of a double field in a Message
func (msg *Message) SetDoubleField(name string, idx int, val float64) error {
	Cbuf := unsafe.Pointer(&val)
	return msg.setFieldValue(name, idx, Cbuf, 8)
}

// GetEnumField returns the string description of a Message field
// with an enumerated type.
func (msg *Message) GetEnumField(name string, idx int) (string, error) {
	enumValue, err := msg.GetUintField(name, idx)
	if err != nil {
		return "", err
	}

	Cname := C.CString(name)
	defer C.free(unsafe.Pointer(Cname))
	var Ename *C.char
	res := C.nmsg_message_enum_value_to_name(
		msg.message, Cname, C.unsigned(enumValue),
		&Ename,
	)
	if err = nmsgError(res); err != nil {
		return "", err
	}
	return C.GoString(Ename), nil
}

// SetEnumField sets the value of the named Message field to the value
// corresponding to the supplied description.
func (msg *Message) SetEnumField(name string, idx int, vname string) error {
	Cname := C.CString(name)
	defer C.free(unsafe.Pointer(Cname))
	Cvname := C.CString(vname)
	defer C.free(unsafe.Pointer(Cvname))

	var v C.uint
	res := C.nmsg_message_enum_name_to_value(msg.message, Cname, Cvname, &v)
	if err := nmsgError(res); err != nil {
		return err
	}
	return msg.SetUintField(name, idx, 32, uint64(v))
}

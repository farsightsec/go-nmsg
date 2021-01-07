/*
 * Copyright (c) 2017 by Farsight Security, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package nmsg

import (
	"encoding/binary"
	"time"

	"google.golang.org/protobuf/proto"
)

// Payload encapsulates an nmsg message in a NmsgPayload, suitable for sending to
// an Output
func Payload(m Message) (*NmsgPayload, error) {
	mbytes, err := proto.Marshal(m)
	if err != nil {
		return nil, err
	}
	now := time.Now().UnixNano()
	return &NmsgPayload{
		Vid:      proto.Uint32(m.GetVid()),
		Msgtype:  proto.Uint32(m.GetMsgtype()),
		TimeSec:  proto.Int64(now / 1000000000),
		TimeNsec: proto.Uint32(uint32(now % 1000000000)),
		Payload:  mbytes,
	}, nil
}

// SetSource sets the NmsgPayload source identifier.
func (p *NmsgPayload) SetSource(s uint32) {
	p.Source = proto.Uint32(s)
}

// SetOperator sets the NmsgPayload operator identifier.
func (p *NmsgPayload) SetOperator(o uint32) {
	p.Operator = proto.Uint32(o)
}

// SetGroup sets the NmsgPayload group identifier.
func (p *NmsgPayload) SetGroup(g uint32) {
	p.Group = proto.Uint32(g)
}

// Message returns the message encapsulated in the NmsgPayload,
// Unmarshaled
func (p *NmsgPayload) Message() (Message, error) {
	m, err := NewMessage(*p.Vid, *p.Msgtype)
	if err != nil {
		return nil, err
	}
	err = proto.Unmarshal(p.Payload, m)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func (p *NmsgPayload) payloadSize() int {
	var ibuf [binary.MaxVarintLen64]byte

	psiz := proto.Size(p)
	// tag + varint length of encoded p
	psiz += 1 + binary.PutUvarint(ibuf[:], uint64(psiz))
	// tag + varint CRC32
	psiz += 1 + binary.MaxVarintLen32
	return psiz
}

/*
 * Copyright (c) 2023 DomainTools LLC
 * Copyright (c) 2017 by Farsight Security, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package nmsg_base

import (
	"github.com/dnstap/golang-dnstap"
	"github.com/farsightsec/go-nmsg"
	"google.golang.org/protobuf/proto"
)

func (p *Ncap) GetVid() uint32     { return 1 }
func (p *Ncap) GetMsgtype() uint32 { return 1 }

func (p *Email) GetVid() uint32     { return 1 }
func (p *Email) GetMsgtype() uint32 { return 2 }

func (p *Linkpair) GetVid() uint32     { return 1 }
func (p *Linkpair) GetMsgtype() uint32 { return 3 }

func (p *Http) GetVid() uint32     { return 1 }
func (p *Http) GetMsgtype() uint32 { return 4 }

func (p *IPConn) GetVid() uint32     { return 1 }
func (p *IPConn) GetMsgtype() uint32 { return 5 }

func (p *LogLine) GetVid() uint32     { return 1 }
func (p *LogLine) GetMsgtype() uint32 { return 6 }

func (p *Dns) GetVid() uint32     { return 1 }
func (p *Dns) GetMsgtype() uint32 { return 7 }

func (p *Pkt) GetVid() uint32     { return 1 }
func (p *Pkt) GetMsgtype() uint32 { return 8 }

func (p *DnsQR) GetVid() uint32     { return 1 }
func (p *DnsQR) GetMsgtype() uint32 { return 9 }

func (p *Xml) GetVid() uint32     { return 1 }
func (p *Xml) GetMsgtype() uint32 { return 10 }

func (p *Encode) GetVid() uint32     { return 1 }
func (p *Encode) GetMsgtype() uint32 { return 11 }

func (p *Packet) GetVid() uint32     { return 1 }
func (p *Packet) GetMsgtype() uint32 { return 12 }

type Dnstap struct {
	dnstap.Dnstap
}

func (d *Dnstap) GetVid() uint32     { return 1 }
func (d *Dnstap) GetMsgtype() uint32 { return 13 }

func (d *Dnstap) Marshal() ([]byte, error) {
	return proto.Marshal(&d.Dnstap)
}
func (d *Dnstap) Unmarshal(b []byte) error {
	return proto.Unmarshal(b, &d.Dnstap)
}

func (d *DnsObs) GetVid() uint32     { return 1 }
func (d *DnsObs) GetMsgtype() uint32 { return 14 }

func init() {
	nmsg.RegisterVendor("base", 1)
	nmsg.Register(&Ncap{})
	nmsg.Register(&Email{})
	nmsg.Register(&Linkpair{})
	nmsg.Register(&Http{})
	nmsg.Register(&IPConn{})
	nmsg.Register(&LogLine{})
	nmsg.Register(&Dns{})
	nmsg.Register(&Pkt{})
	nmsg.Register(&DnsQR{})
	nmsg.Register(&Xml{})
	nmsg.Register(&Encode{})
	nmsg.Register(&Packet{})
	nmsg.Register(&Dnstap{})
	nmsg.Register(&DnsObs{})
}

/*
 * Copyright (c) 2018 by Farsight Security, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package nmsg

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// A Sockspec is an address of a single socket (addr/port) or a series of
// sockets with contiguous port numbers (addr/loport..hiport)
type Sockspec struct {
	Addr   *net.UDPAddr
	Hiport int
}

// ParseSockspec creates a Sockspec from its text representaion v.
func ParseSockspec(v string) (*Sockspec, error) {
	s := &Sockspec{}
	return s, s.Set(v)
}

// Set initializes a Sockspec from its text representation v. Set satisfies
// flag.Value allowing a sockspec to be conveniently specified as a command
// line parameter.
func (s *Sockspec) Set(v string) error {
	l := strings.SplitN(v, "/", 2)
	if len(l) != 2 {
		return fmt.Errorf("Invalid sockspec: %s", v)
	}
	p := strings.SplitN(l[1], "..", 2)
	addr := fmt.Sprintf("%s:%s", l[0], p[0])
	uaddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("Invalid addr %s: %v", addr, err)
	}
	s.Addr = uaddr
	if len(p) == 1 {
		s.Hiport = uaddr.Port
		return nil
	}

	hiport, err := strconv.ParseUint(p[1], 10, 16)
	if err != nil {
		return fmt.Errorf("Invalid high port %s: %v", p[1], err)
	}

	if int(hiport) <= uaddr.Port {
		return fmt.Errorf("Invalid port range %s", l[1])
	}
	s.Hiport = int(hiport)
	return nil
}

// UnmarshalJSON satisifies json.Unmarshaler allowing Sockspecs to be parsed
// from JSON configurations.
func (s *Sockspec) UnmarshalJSON(b []byte) error {
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	return s.Set(v)
}

// UnmarshalYAML satisifies yaml.Unmarshaler allowing Sockspecs to be parsed
// from YAML configurations.
func (s *Sockspec) UnmarshalYAML(u func(interface{}) error) error {
	var v string
	if err := u(&v); err != nil {
		return err
	}
	return s.Set(v)
}

// Addrs returns the list of UDP socket addresses of the Sockspec, or nil
// if the Sockspec is uninitialized.
func (s *Sockspec) Addrs() []*net.UDPAddr {
	var addrs []*net.UDPAddr
	if s.Addr == nil {
		return nil
	}
	for i := s.Addr.Port; i <= s.Hiport; i++ {
		a := &net.UDPAddr{}
		*a = *s.Addr
		a.Port = i
		addrs = append(addrs, a)
	}
	return addrs
}

// String returns the string representation of the Sockspec. If the Sockspec
// is uninitialized, String returns the empty string.
func (s *Sockspec) String() string {
	if s.Addr == nil {
		return ""
	}
	if s.Hiport > s.Addr.Port {
		return fmt.Sprintf("%s/%d..%d", s.Addr.IP.String(),
			s.Addr.Port, s.Hiport)
	}
	return fmt.Sprintf("%s/%d", s.Addr.IP.String(), s.Addr.Port)
}

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
	"testing"

	yaml "gopkg.in/yaml.v2"
)

var sockspecTestCases = []struct {
	sockspec string
	valid    bool
	naddrs   int
}{
	{"127.0.0.1/382", true, 1},
	{"127.0.0.1/382..390", true, 9},
	{"foobar", false, 0},
	{"127.0.0.1/foobar", false, 0},
	{"127.0.0.1/390..382", false, 0},
	{"127.0.0.1/390..foobar", false, 0},
	{"invalid_hostname/381", false, 0},
}

func testSockSpecCommon(t *testing.T, parse func(string, *Sockspec) error) {
	t.Helper()
	for _, tc := range sockspecTestCases {
		var ss Sockspec
		if err := parse(tc.sockspec, &ss); err != nil {
			if tc.valid {
				t.Errorf("%s: %v", tc.sockspec, err)
			}
			continue
		}
		if !tc.valid {
			t.Errorf("parsed invalid sockspec %s", tc.sockspec)
			continue
		}
		if len(ss.Addrs()) != tc.naddrs {
			t.Errorf("%s: expected %d addrs, got %d", tc.sockspec,
				tc.naddrs, len(ss.Addrs()))
		}
		if ss.String() != tc.sockspec {
			t.Errorf("%s parsed to %s (%#v)", tc.sockspec, &ss, ss)
		}
	}
}

func TestSockSpecSet(t *testing.T) {
	testSockSpecCommon(t, func(s string, ss *Sockspec) error {
		return ss.Set(s)
	})
}

func TestSockSpecParse(t *testing.T) {
	testSockSpecCommon(t, func(s string, ss *Sockspec) error {
		parsed, err := ParseSockspec(s)
		*ss = *parsed
		return err
	})
}

func TestSockSpecJSON(t *testing.T) {
	testSockSpecCommon(t, func(s string, ss *Sockspec) error {
		b, err := json.Marshal(s)
		if err != nil {
			return err
		}
		return json.Unmarshal(b, ss)
	})
}

func TestSockSpecYAML(t *testing.T) {
	testSockSpecCommon(t, func(s string, ss *Sockspec) error {
		b, err := yaml.Marshal(s)
		if err != nil {
			return err
		}
		return yaml.Unmarshal(b, ss)
	})
}

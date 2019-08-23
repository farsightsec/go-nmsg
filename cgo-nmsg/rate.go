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
import "runtime"

// A Rate provides Rate limiting across one or more outputs.
type Rate struct{ rate C.nmsg_rate_t }

// NewRate initializes and returns a rate context. The rate parameter
// specifies the target rate of packets (containers and fragments) sent
// on all outputs using the Rate. The freq parameter specifies how often
// (in packets) to check the rate limit.
func NewRate(rate, freq uint) *Rate {
	r := &Rate{C.nmsg_rate_init(C.uint(rate), C.uint(freq))}
	runtime.SetFinalizer(r, func(r *Rate) {
		C.nmsg_rate_destroy(&r.rate)
	})
	return r
}

// Sleep pauses for an appropriate amount of time to maintain the given
// output rate.
func (r *Rate) Sleep() {
	C.nmsg_rate_sleep(r.rate)
}

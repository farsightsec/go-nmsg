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

int nmsg_wbufsiz_min = NMSG_WBUFSZ_MIN;
int nmsg_wbufsiz_max = NMSG_WBUFSZ_MAX;
int nmsg_wbufsiz_ether = NMSG_WBUFSZ_ETHER;
int nmsg_wbufsiz_jumbo = NMSG_WBUFSZ_JUMBO;
*/
import "C"

func init() {
	if C.nmsg_init() != C.nmsg_res_success {
		panic("failed to initialize nmsg library")
	}
}

// Buffer Size constants from libnmsg
var (
	BufferSizeMax   = int(C.nmsg_wbufsiz_max)
	BufferSizeMin   = int(C.nmsg_wbufsiz_min)
	BufferSizeEther = int(C.nmsg_wbufsiz_ether)
	BufferSizeJumbo = int(C.nmsg_wbufsiz_jumbo)
)

// SetDebug sets the debug print level for the nmsg library.
// Debugging messages are sent to stderr. Higher debug values
// increase verbosity.
func SetDebug(debug int) {
	C.nmsg_set_debug(C.int(debug))
}

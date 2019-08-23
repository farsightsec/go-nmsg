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
*/
import "C"

// NmsgError encapsulates an error condition
type nmsgResError C.nmsg_res

func (n nmsgResError) Error() string {
	return C.GoString(C.nmsg_res_lookup(uint32(n)))
}

func nmsgError(res C.nmsg_res) error {
	if res == C.nmsg_res_success {
		return nil
	}
	return nmsgResError(res)
}

// ErrorRetry returns true if the error indicates that the nmsg
// operation should be retried.
func ErrorRetry(err error) bool {
	if ne, ok := err.(nmsgResError); ok {
		return ne == nmsgResError(C.nmsg_res_again)
	}
	return false
}

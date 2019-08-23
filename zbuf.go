/*
 * Copyright (c) 2017 by Farsight Security, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package nmsg

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"io"
)

func zbufDeflate(b []byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint32(len(b)))
	w := zlib.NewWriter(buf)
	if _, err := w.Write(b); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func zbufInflate(b []byte) ([]byte, error) {
	br := bytes.NewReader(b)
	var ilen uint32
	binary.Read(br, binary.BigEndian, &ilen)
	buf := bytes.NewBuffer(make([]byte, 0, int(ilen)))
	r, err := zlib.NewReader(br)
	if err != nil {
		return nil, err
	}
	if _, err = io.Copy(buf, r); err != nil {
		return nil, err
	}
	r.Close()
	return buf.Bytes(), nil
}

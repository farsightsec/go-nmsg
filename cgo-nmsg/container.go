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
import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"runtime"
	"sync"
	"unsafe"
)

// A Container is a collection of NMSG payloads with a target size.
type Container struct {
	config         ContainerConfig
	sequenceID     uint64
	sequenceNumber uint32
	container      C.nmsg_container_t
}

// ContainerConfig contains
type ContainerConfig struct {
	Compress bool
	Sequence bool
	Size     int
}

// NewContainer creates a container with the given target size.
func NewContainer(conf *ContainerConfig) *Container {
	c := &Container{config: *conf, container: C.nmsg_container_init(C.size_t(conf.Size))}
	runtime.SetFinalizer(c, func(c *Container) {
		C.nmsg_container_destroy(&c.container)
	})
	if conf.Sequence {
		C.nmsg_container_set_sequence(c.container, C.bool(true))
		binary.Read(rand.Reader, binary.BigEndian, &c.sequenceID)
	}
	return c
}

// ErrorFull returns true if the container is full. If the Container Add()
// method returns such an error, the message will need to be added to the
// next container.
func ErrorFull(err error) bool {
	t, ok := err.(nmsgResError)
	return ok && t == nmsgResError(C.nmsg_res_container_full)
}

// ErrorOverfull returns true if the container contains a single payload
// and its size is greater than the target size.
func ErrorOverfull(err error) bool {
	t, ok := err.(nmsgResError)
	return ok && t == nmsgResError(C.nmsg_res_container_overfull)
}

// Add adds the supplied Message to the Container.
func (c *Container) Add(m *Message) error {
	return nmsgError(C.nmsg_container_add(c.container, m.message))
}

// Bytes returns the serialized container and resets the container.
func (c *Container) Bytes() []byte {
	var pbuf *C.uint8_t
	var pbufLen C.size_t
	res := C.nmsg_container_serialize(c.container,
		&pbuf, &pbufLen,
		C.bool(true),
		C.bool(c.config.Compress),
		C.uint32_t(c.sequenceNumber),
		C.uint64_t(c.sequenceID),
	)
	defer C.free(unsafe.Pointer(pbuf))
	if err := nmsgError(res); err != nil {
		return nil
	}
	c.sequenceID++
	C.nmsg_container_destroy(&c.container)
	c.container = C.nmsg_container_init(C.size_t(c.config.Size))
	if c.config.Sequence {
		C.nmsg_container_set_sequence(c.container, C.bool(true))
	}

	return C.GoBytes(unsafe.Pointer(pbuf), C.int(pbufLen))
}

// UnpackContainer returns the messages the container contains.
func UnpackContainer(b []byte) ([]*Message, error) {
	var msgarray *C.nmsg_message_t
	var nmsgs C.size_t

	res := C.nmsg_container_deserialize(
		(*C.uint8_t)(unsafe.Pointer(&b[0])),
		C.size_t(len(b)),
		&msgarray,
		&nmsgs)
	if err := nmsgError(res); err != nil {
		return nil, err
	}
	msgs := make([]*Message, 0, int(nmsgs))
	p := unsafe.Pointer(msgarray)
	for i := 0; i < int(nmsgs); i++ {
		mp := unsafe.Pointer(uintptr(p) + uintptr(i)*unsafe.Sizeof(*msgarray))
		msgs = append(msgs, messageFromC(*(*C.nmsg_message_t)(mp)))
	}

	C.free(unsafe.Pointer(msgarray))
	return msgs, nil
}

// A ContainerOutput writes containers to a generic io.Writer. No fragmentation
// of oversize containers is performed.
type containerOutput struct {
	mu            sync.Mutex
	w             io.Writer
	c             *Container
	rate          *Rate
	buffered      bool
	empty         bool
	filtervendor  uint32
	filtermsgtype uint32
	source        uint32
	operator      uint32
	group         uint32
}

// NewContainerOutput creates a ContainerOutput writing to the supplied
// io.Writer with the given buffer size.
func newContainerOutput(w io.Writer, size int) *containerOutput {
	return &containerOutput{
		c: NewContainer(&ContainerConfig{
			Size:     size,
			Sequence: true,
		}),
		buffered: true,
		empty:    true,
		w:        w,
	}
}

func (co *containerOutput) Write(m *Message) error {
	for {
		vid, msgtype := m.GetMsgtype()
		if co.filtervendor > 0 && co.filtervendor != vid {
			return nil
		}
		if co.filtermsgtype > 0 && co.filtermsgtype != msgtype {
			return nil
		}
		if co.source > 0 {
			m.SetSource(co.source)
		}
		if co.operator > 0 {
			m.SetOperator(co.operator)
		}
		if co.group > 0 {
			m.SetGroup(co.group)
		}

		co.mu.Lock()
		err := co.c.Add(m)
		if co.buffered && err == nil {
			co.empty = false
			co.mu.Unlock()
			return nil
		}
		_, werr := co.w.Write(co.c.Bytes())
		co.empty = true
		r := co.rate
		co.mu.Unlock()
		if r != nil {
			r.Sleep()
		}
		if werr == nil && ErrorFull(err) {
			continue
		}
		return werr
	}
}

// SetFilterMsgtype instructs the output to only accept Messages
// with the given vendor and messagetype, specified by id.
func (co *containerOutput) SetFilterMsgtype(vendor, msgtype uint32) {
	co.filtervendor = vendor
	co.filtermsgtype = msgtype
}

// SetFilterMsgtypeByname instructs the output to only accept Messages
// with the given vendor and messagetype, specified by name.
func (co *containerOutput) SetFilterMsgtypeByname(vendor, msgtype string) {
	cvendor := C.CString(vendor)
	cmsgtype := C.CString(msgtype)
	defer C.free(unsafe.Pointer(cvendor))
	defer C.free(unsafe.Pointer(cmsgtype))
	cvid := C.nmsg_msgmod_vname_to_vid(cvendor)
	co.filtervendor = uint32(cvid)
	co.filtermsgtype = uint32(C.nmsg_msgmod_mname_to_msgtype(cvid, cmsgtype))
}

func (co *containerOutput) SetRate(r *Rate) {
	co.mu.Lock()
	co.rate = r
	co.mu.Unlock()
}

func (co *containerOutput) SetSource(source uint32) {
	co.source = source
}

func (co *containerOutput) SetOperator(op uint32) {
	co.operator = op
}

func (co *containerOutput) SetGroup(group uint32) {
	co.group = group
}

// Flush writes any buffered output to the underlying writer.
func (co *containerOutput) Flush() error {
	co.mu.Lock()
	written := false
	defer func() {
		r := co.rate
		co.mu.Unlock()
		if written && r != nil {
			r.Sleep()
		}
	}()
	if !co.empty {
		_, werr := co.w.Write(co.c.Bytes())
		co.empty = true
		written = true
		return werr
	}
	return nil
}

// SetBuffered controls whether the ContainerOutput collects
// multiple messages into a container (buffered == true, the
// default), or sends a container per message (buffered == false).
func (co *containerOutput) SetBuffered(buffered bool) {
	co.buffered = buffered
}

// SetCompression controls whether the containers are compressed
// before sending.
func (co *containerOutput) SetCompression(compress bool) {
	co.c.config.Compress = compress
}

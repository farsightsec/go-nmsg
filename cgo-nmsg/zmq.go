package nmsg

/*
#cgo pkg-config: libnmsg libzmq
#cgo LDFLAGS: -lnmsg -lzmq
#include <stdlib.h>
#include <nmsg.h>
#include <zmq.h>
*/
import "C"
import (
	"errors"
	"unsafe"
)

var zmqContext unsafe.Pointer

func init() {
	zmqContext = C.zmq_init(1)
}

// NewZMQInput opens an Input reading from the given ZMQ endpoint.
func NewZMQInput(zmqep string) (Input, error) {
	czmqep := C.CString(zmqep)
	defer C.free(unsafe.Pointer(czmqep))
	inp := C.nmsg_input_open_zmq_endpoint(zmqContext, czmqep)
	if inp == nil {
		return nil, errors.New("failed to create NMSG input")
	}
	return &nmsgInput{input: inp}, nil
}

// NewZMQInput creates an output writing to the given ZMQ endpoint.
func NewZMQOutput(zmqep string, bufsiz int) (Output, error) {
	czmqep := C.CString(zmqep)
	defer C.free(unsafe.Pointer(czmqep))
	outp := C.nmsg_output_open_zmq_endpoint(zmqContext, czmqep, C.size_t(bufsiz))
	if outp == nil {
		return nil, errors.New("failed to create NMSG output")
	}
	return &nmsgOutput{output: outp}, nil
}

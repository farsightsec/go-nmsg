package nmsg_test

import (
	"errors"
	"github.com/farsightsec/go-nmsg"
	"io"
	"reflect"
	"testing"
)

func PayloadIsEqual(c *nmsg.NmsgPayload, d *nmsg.NmsgPayload) bool {
	if *c.Vid != *d.Vid || *c.Msgtype != *d.Msgtype {
		return false
	}

	return reflect.DeepEqual(c.Payload, d.Payload)
}

func doTestDo(t * testing.T, i nmsg.Input, o nmsg.Output) {
	pout, err := nmsg.Payload(testMessage(900))
	if err != nil {
		t.Error(err.Error())
		return
	}

	err = o.Send(pout)
	if err != nil {
		t.Error(err.Error())
		return
	}

	pin, err := i.Recv()
	if err != nil {
		t.Error(err.Error())
		return
	}

	if PayloadIsEqual(pout, pin) == false {
		t.Error(errors.New("Failed to compare in and out payloads"))
	}
}

func doTestUnbuffered(t *testing.T, r io.Reader, w io.Writer) {
	input := nmsg.NewInput(r, 1000)
	output := nmsg.UnbufferedOutput(w)

	doTestDo(t, input, output)
}

func doTestBuffered(t *testing.T, r io.Reader, w io.Writer) {
	input := nmsg.NewInput(r, 1000)
	output := nmsg.BufferedOutput(w)

	doTestDo(t, input, output)
}

func TestZMQLocal(t *testing.T) {
	reader, err := nmsg.ZMQReader("tcp://127.0.0.1:5555,accept,pushpull")

	if err != nil {
		t.Error(err.Error())
		return
	}

	writer, err := nmsg.ZMQWriter("tcp://127.0.0.1:5555,connect,pushpull")

	if err != nil {
		t.Error(err.Error())
		return
	}

	doTestUnbuffered(t, reader, writer)
	doTestBuffered(t, reader, writer)

}

func TestZMQInproc(t *testing.T) {
	reader, err := nmsg.ZMQReader("inproc://TestZMQInproc,accept,pushpull")

	if err != nil {
		t.Error(err.Error())
		return
	}

	writer, err := nmsg.ZMQWriter("inproc://TestZMQInproc,connect,pushpull")

	if err != nil {
		t.Error(err.Error())
		return
	}

	doTestUnbuffered(t, reader, writer)
	doTestBuffered(t, reader, writer)
}

func TestZMQIpc(t *testing.T) {
	reader, err := nmsg.ZMQReader("ipc:///tmp/TestZMQIpc,accept,pushpull")

	if err != nil {
		t.Error(err.Error())
		return
	}

	writer, err := nmsg.ZMQWriter("ipc:///tmp/TestZMQIpc,connect,pushpull")

	if err != nil {
		t.Error(err.Error())
		return
	}

	doTestUnbuffered(t, reader, writer)
	doTestBuffered(t, reader, writer)
}

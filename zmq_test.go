package nmsg_test

import (
	"errors"
	"github.com/farsightsec/go-nmsg"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"
)

func PayloadIsEqual(c *nmsg.NmsgPayload, d *nmsg.NmsgPayload) bool {
	if *c.Vid != *d.Vid || *c.Msgtype != *d.Msgtype {
		return false
	}

	return reflect.DeepEqual(c.Payload, d.Payload)
}

func doTestDo(t *testing.T, i nmsg.Input, o nmsg.Output) {

	signal := make(chan bool)

	pout, err := nmsg.Payload(testMessage(900))
	if err != nil {
		t.Error(err.Error())
		return
	}

	go func() {
		for {
			select {
			case _ = <-signal:
				break
			default:
				err = o.Send(pout)
				if err != nil {
					t.Error(err.Error())
					return
				}
			}
		}
	}()

	pin, err := i.Recv()
	if err != nil {
		t.Error(err.Error())
		return
	}

	signal <- true

	if PayloadIsEqual(pout, pin) == false {
		t.Error(errors.New("Failed to compare in and out payloads"))
	}
}

func doUnbind(o io.Writer) error {
	if obj, ok := o.(interface{ Unbind() error }); ok {
		return obj.Unbind()
	}
	return nil
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

type tester func(*testing.T, io.Reader, io.Writer)

func doTestFor(t *testing.T, ep string, tp string, fn tester) {
	writer, err := nmsg.ZMQWriter(ep + ",accept," + tp)

	if err != nil {
		t.Error(err.Error())
		return
	}

	reader, err := nmsg.ZMQReader(ep + ",connect," + tp)

	if err != nil {
		t.Error(err.Error())
		return
	}

	fn(t, reader, writer)
	if strings.HasPrefix(ep, "tcp") || strings.HasPrefix(ep, "inproc") {
		doUnbind(writer)
		// Have to sleep to allow ZMQ unbind to finish for TCP
		time.Sleep(1000 * 1000 * 10)
	}
}

func TestZMQLocal(t *testing.T) {
	doTestFor(t, "tcp://127.0.0.1:5555", "pushpull", doTestUnbuffered)
	doTestFor(t, "tcp://127.0.0.1:5555", "pushpull", doTestBuffered)
	doTestFor(t, "tcp://127.0.0.1:5556", "pubsub", doTestUnbuffered)
	doTestFor(t, "tcp://127.0.0.1:5556", "pubsub", doTestBuffered)
}

func TestZMQInproc(t *testing.T) {
	doTestFor(t, "inproc://TestZMQInproc1", "pushpull", doTestUnbuffered)
	doTestFor(t, "inproc://TestZMQInproc1", "pushpull", doTestBuffered)
	doTestFor(t, "inproc://TestZMQInproc2", "pubsub", doTestUnbuffered)
	doTestFor(t, "inproc://TestZMQInproc2", "pubsub", doTestBuffered)
}

func TestZMQIpc(t *testing.T) {
	doTestFor(t, "ipc:///tmp/TestZMQIpc1", "pushpull", doTestUnbuffered)
	doTestFor(t, "ipc:///tmp/TestZMQIpc1", "pushpull", doTestBuffered)
	doTestFor(t, "ipc:///tmp/TestZMQIpc2", "pubsub", doTestUnbuffered)
	doTestFor(t, "ipc:///tmp/TestZMQIpc2", "pubsub", doTestBuffered)
}

package nmsg_test

import (
	"errors"
	"github.com/farsightsec/go-nmsg"
	cnmsg "github.com/farsightsec/go-nmsg/cgo-nmsg"
	"io"
	"log"
	"strconv"
	"testing"
)

type tester func(*testing.T, io.Reader, io.Writer)
type testerCgo func(*testing.T, cnmsg.Input, cnmsg.Output)
type testerMixed func(*testing.T, cnmsg.Input, cnmsg.Output, nmsg.Input, nmsg.Output)

func PayloadIsEqual(c *nmsg.NmsgPayload, d *nmsg.NmsgPayload) bool {
	if *c.Vid != *d.Vid || *c.Msgtype != *d.Msgtype {
		return false
	}

	return compare(c.Payload, d.Payload)
}

func MessageIsEqual(c *cnmsg.Message, d *cnmsg.Message) bool {
	ct, cv := c.GetMsgtype()
	dt, dv := d.GetMsgtype()
	if ct != dt || cv != dv {
		return false
	}

	cp, err := c.GetBytesField("payload", 0)
	if err != nil {
		return false
	}

	dp, err := d.GetBytesField("payload", 0)
	if err != nil {
		return false
	}

	return compare(cp, dp)
}

func getCgoMessage(t *testing.T, size int) *cnmsg.Message {
	mod := cnmsg.MessageModLookupByName("base", "encode")
	if mod == nil {
		log.Fatal("module not found")
	}
	msg := cnmsg.NewMessage(mod)
	if err := msg.SetEnumField("type", 0, "TEXT"); err != nil {
		log.Fatal(err)
	}

	payload := make([]byte, size)
	for i := range payload {
		payload[i] = '0'
	}

	if err := msg.SetBytesField("payload", 0, payload); err != nil {
		log.Fatal(err)
	}

	return msg
}

func doWriteCgo(t *testing.T, s chan bool, o cnmsg.Output) error {
	for {
		select {
		case _ = <-s:
			return nil
		default:
			msg := getCgoMessage(t, 500)
			err := o.Write(msg)
			if err != nil {
				return err
			}
		}
	}
}

func doReadCGo(s chan bool, i cnmsg.Input) (*cnmsg.Message, error) {
	var rmsg *cnmsg.Message
	var err error
	for {
		rmsg, err = i.Read()
		if err != nil {
			if cnmsg.ErrorRetry(err) == false {
				return nil, err
			}
		} else if rmsg == nil {
			return nil, errors.New("receive nil message")
		} else {
			break
		}
	}
	s <- true
	return rmsg, nil
}

func doWriteNmsg(s chan bool, msg *nmsg.NmsgPayload, o nmsg.Output) error {
	for {
		select {
		case _ = <-s:
			return nil
		default:
			err := o.Send(msg)
			if err != nil {
				return err
			}
		}
	}
}

func doReadNmsg(s chan bool, i nmsg.Input) (*nmsg.NmsgPayload, error) {
	var rmsg *nmsg.NmsgPayload
	var err error
	for {
		rmsg, err = i.Recv()
		if err != nil {
			return nil, err
		} else if rmsg == nil {
			return nil, errors.New("receive nil message")
		} else {
			break
		}
	}
	s <- true
	return rmsg, nil
}

func doTestDo(t *testing.T, i nmsg.Input, o nmsg.Output) {

	signal := make(chan bool)

	pout, err := nmsg.Payload(testMessage(900))
	if err != nil {
		t.Error(err.Error())
		return
	}

	go func() {
		err := doWriteNmsg(signal, pout, o)
		if err != nil {
			t.Fatal(err.Error())
		}
	}()

	pin, err := doReadNmsg(signal, i)
	if err != nil {
		t.Error(err.Error())
		return
	}

	if PayloadIsEqual(pout, pin) == false {
		t.Error(errors.New("Failed to compare in and out payloads"))
	}
}

func doTestCgoDo(t *testing.T, i cnmsg.Input, o cnmsg.Output) {
	signal := make(chan bool)

	go func() {
		err := doWriteCgo(t, signal, o)
		if err != nil {
			t.Fatal(err.Error())
		}
	}()

	rmsg, err := doReadCGo(signal, i)

	if err != nil {
		t.Fatal(err.Error())
	}

	msg_ref := getCgoMessage(t, 500)
	if MessageIsEqual(rmsg, msg_ref) == false {
		log.Fatal("messages do not match")
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

func doTestFor(t *testing.T, ep string, tp string, fn tester) {
	writer, err := nmsg.NewZMQWriter(ep + ",accept," + tp)

	if err != nil {
		t.Error(err.Error())
		return
	}

	reader, err := nmsg.NewZMQReader(ep + ",connect," + tp)

	if err != nil {
		t.Error(err.Error())
		return
	}

	fn(t, reader, writer)
}

func doTestForCGo(t *testing.T, ep string, tp string, fn testerCgo) {
	writer, err := cnmsg.NewZMQOutput(ep+",accept,"+tp, 2000)

	if err != nil {
		t.Error(err.Error())
		return
	}

	reader, err := cnmsg.NewZMQInput(ep + ",connect," + tp)

	if err != nil {
		t.Error(err.Error())
		return
	}

	fn(t, reader, writer)
}

func doTestMixedDo(t *testing.T, ci cnmsg.Input, co cnmsg.Output, ni nmsg.Input, no nmsg.Output) {
	// Write to co, read for ni, write to no, read from ci
	signal1 := make(chan bool)
	signal2 := make(chan bool)

	go func() {
		err := doWriteCgo(t, signal1, co)
		if err != nil {
			log.Fatal(err.Error())
		}
	}()
	pin, err := doReadNmsg(signal1, ni)
	if err != nil {
		log.Fatal(err.Error())
	}
	go func() {
		err := doWriteNmsg(signal2, pin, no)
		if err != nil {
			log.Fatal(err.Error())
		}
	}()
	rmsg, err := doReadCGo(signal2, ci)
	if err != nil {
		log.Fatal(err.Error())
	}

	msg_ref := getCgoMessage(t, 500)

	if MessageIsEqual(rmsg, msg_ref) == false {
		log.Fatal("messages do not match")
	}
}

func doTestForMixed(t *testing.T, ep string, num int, tp string, fn testerMixed) {
	ep1 := ep + strconv.Itoa(num)
	ep2 := ep + strconv.Itoa(num+1)

	co, err := cnmsg.NewZMQOutput(ep1+",accept,"+tp, 1000)

	if err != nil {
		t.Error(err.Error() + " " + ep1)
		return
	}

	nw, err := nmsg.NewZMQWriter(ep2 + ",accept," + tp)
	if err != nil {
		t.Error(err.Error() + " " + ep2)
		return
	}

	nr, err := nmsg.NewZMQReader(ep1 + ",connect," + tp)
	if err != nil {
		t.Error(err.Error() + " " + ep1)
		return
	}

	ci, err := cnmsg.NewZMQInput(ep2 + ",connect," + tp)

	if err != nil {
		t.Error(err.Error() + " " + ep2)
		return
	}

	ni := nmsg.NewInput(nr, 1000)
	no := nmsg.UnbufferedOutput(nw)

	fn(t, ci, co, ni, no)
}

func TestZMQLocal(t *testing.T) {
	doTestFor(t, "tcp://127.0.0.1:5555", "pushpull", doTestUnbuffered)
	doTestFor(t, "tcp://127.0.0.1:5556", "pushpull", doTestBuffered)
	doTestFor(t, "tcp://127.0.0.1:5557", "pubsub", doTestUnbuffered)
	doTestFor(t, "tcp://127.0.0.1:5558", "pubsub", doTestBuffered)
}

func TestZMQInproc(t *testing.T) {
	doTestFor(t, "inproc://TestZMQInproc1", "pushpull", doTestUnbuffered)
	doTestFor(t, "inproc://TestZMQInproc2", "pushpull", doTestBuffered)
	doTestFor(t, "inproc://TestZMQInproc3", "pubsub", doTestUnbuffered)
	doTestFor(t, "inproc://TestZMQInproc4", "pubsub", doTestBuffered)
}

func TestZMQIpc(t *testing.T) {
	doTestFor(t, "ipc:///tmp/TestZMQIpc1", "pushpull", doTestUnbuffered)
	doTestFor(t, "ipc:///tmp/TestZMQIpc1", "pushpull", doTestBuffered)
	doTestFor(t, "ipc:///tmp/TestZMQIpc2", "pubsub", doTestUnbuffered)
	doTestFor(t, "ipc:///tmp/TestZMQIpc2", "pubsub", doTestBuffered)
}

func TestZMQ_CGo_Local(t *testing.T) {
	doTestForCGo(t, "tcp://127.0.0.1:6555", "pushpull", doTestCgoDo)
	doTestForCGo(t, "tcp://127.0.0.1:6557", "pubsub", doTestCgoDo)
}

func TestZMQ_CGo_Inproc(t *testing.T) {
	doTestForCGo(t, "inproc://TestZMQInproc10", "pushpull", doTestCgoDo)
	doTestForCGo(t, "inproc://TestZMQInproc30", "pubsub", doTestCgoDo)
}

func TestZMQ_CGo_IPC(t *testing.T) {
	doTestForCGo(t, "ipc:///tmp/TestZMQIpc10", "pushpull", doTestCgoDo)
	doTestForCGo(t, "ipc:///tmp/TestZMQIpc20", "pubsub", doTestCgoDo)
}

func TestZmq_Mixed_Local(t *testing.T) {
	doTestForMixed(t, "tcp://127.0.0.1:", 7555, "pushpull", doTestMixedDo)
	doTestForMixed(t, "tcp://127.0.0.1:", 7557, "pubsub", doTestMixedDo)
}

//// Inproc cgo-nmsg side fill writer buffer and hangs
//func TestZmq_Mixed_Inproc(t *testing.T) {
//	doTestForMixed(t, "inproc://TestZMQInproc", 100, "pushpull", doTestMixedDo)
//	doTestForMixed(t, "inproc://TestZMQInproc", 200, "pubsub", doTestMixedDo)
//}

func TestZmq_Mixed_IPC(t *testing.T) {
	doTestForMixed(t, "ipc:///tmp/TestZMQIpc", 100, "pushpull", doTestMixedDo)
	doTestForMixed(t, "ipc:///tmp/TestZMQIpc", 200, "pubsub", doTestMixedDo)
}

package nmsg_test

import (
	"errors"
	"github.com/farsightsec/go-nmsg"
	"reflect"
	"testing"
)

func PayloadIsEqual(c *nmsg.NmsgPayload, d *nmsg.NmsgPayload) bool {
	if *c.Vid != *d.Vid || *c.Msgtype != *d.Msgtype {
		return false
	}

	return reflect.DeepEqual(c.Payload, d.Payload)
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

	input := nmsg.NewInput(reader, 1000)
	output := nmsg.UnbufferedOutput(writer)

	pout, err := nmsg.Payload(testMessage(900))
	if err != nil {
		t.Error(err.Error())
		return
	}

	//for i:=0; i<10; i++ {
	err = output.Send(pout)
	if err != nil {
		t.Error(err.Error())
		return
	}
	//}

	output.Close()

	pin, err := input.Recv()
	if err != nil {
		t.Error(err.Error())
		return
	}

	if PayloadIsEqual(pout, pin) == false {
		t.Error(errors.New("Failed to compare in and out payloads"))
	}
}

# Pure Golang NMSG Library

`go-nmsg` is a pure go implementation of the NMSG container and payload
format used by the C (nmsg)[https://github.com/farsightsec/nmsg] toolkit
and library.

## Synopsis

	import "github.com/farsightsec/go-nmsg"
	import "github.com/farsightsec/go-nmsg/nmsg_base"

	var r io.Reader
	var w io.Writer
	...
	input := nmsg.NewInput(r, mtu)
	output := nmsg.BufferedOutput(w)
	output.SetMaxSize(nmsg.MaxContainerSize, 0)

	for {
		payload, err := inp.Recv()
		if err != nil {
			if nmsg.IsDataError(err) {
				continue
			}
			break
		}
		message := payload.Message()

		switch message.(type) {
		case *nmsg_base.Dnstap:
			// process dnstap
			// write copy to output
			output.Send(payload)
		}
	}

	output.Close()


## Requirements

`go-nmsg` requires the following open source libraries:

	"github.com/golang/protobuf/proto"
	"github.com/dnstap/golang-dnstap"

## Limitations

`go-nmsg` can pack and unpack the protobuf structure of an NMSG payload,
and the protobuf structure of the data contained in the payload. It does
not implement the full functionality of the C libnmsg message
modules, such as:

 * Advanced field types (e.g., a protobuf []byte as an IP address)
 * Generated fields
 * Formatting of fields for presentation and JSON output

Applications needing such functionality in go should use the
`cgo-nmsg` package included in this distribution under:

	"github.com/farsightsec/go-nmsg/cgo-nmsg"

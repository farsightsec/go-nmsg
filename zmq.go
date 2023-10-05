package nmsg

import (
	"errors"
	zmq "github.com/pebbe/zmq4"
	"io"
	"strings"
)

type socketKind int
type socketDirection int
type socketType int

const (
	socketInput  socketKind = 0
	socketOutput            = 1
)
const (
	sockdirInvalid socketDirection = 0
	sockdirAccept                  = 1
	sockdirConnect                 = 2
)

const (
	SocktypeInvalid  socketType = 0
	SocktypePubsub              = 1
	SocktypePushpull            = 2
)

func munge_endpoint(ep string) (string, socketDirection, socketType, error) {
	endpoint := ""
	sockdir := sockdirInvalid
	socktype := SocktypeInvalid

	tokens := strings.Split(ep, ",")
	for i, tok := range tokens {
		if i == 0 {
			endpoint = tok
		} else {
			switch tok {
			case "accept":
				if sockdir != sockdirInvalid {
					return "", sockdirInvalid, SocktypeInvalid, errors.New("socket direction is already set")
				}
				sockdir = sockdirAccept
			case "connect":
				if sockdir != sockdirInvalid {
					return "", sockdirInvalid, SocktypeInvalid, errors.New("socket direction is already set")
				}
				sockdir = sockdirConnect
			case "pubsub":
				if socktype != SocktypeInvalid {
					return "", sockdirInvalid, SocktypeInvalid, errors.New("socket type is already set")
				}
				socktype = SocktypePubsub
			case "pushpull":
				if socktype != SocktypeInvalid {
					return "", sockdirInvalid, SocktypeInvalid, errors.New("socket type is already set")
				}
				socktype = SocktypePushpull
			}
		}

	}
	return endpoint, sockdir, socktype, nil
}

func setSocketOptions(socket *zmq.Socket, p zmq.Type) error {
	if p == zmq.SUB {
		return socket.SetSubscribe("NMSG")
	}
	if p == zmq.PUB || p == zmq.PUSH {
		err := socket.SetSndhwm(1000)
		if err == nil {
			err = socket.SetLinger(1000)
		}
		return err
	}
	return nil
}

func zmq_socket_type(kind socketKind, socketType socketType) zmq.Type {
	if kind == socketInput {
		if socketType == SocktypePubsub {
			return zmq.SUB
		} else if socketType == SocktypePushpull {
			return zmq.PULL
		}
	} else if kind == socketOutput {
		if socketType == SocktypePubsub {
			return zmq.PUB
		} else if socketType == SocktypePushpull {
			return zmq.PUSH
		}
	}

	return zmq.Type(-1)
}

func zmq_socket(ep string, kind socketKind) (*zmq.Socket, string, error) {
	endpoint, socketDir, socketType, err := munge_endpoint(ep)

	if err != nil {
		return nil, "", err
	}

	if endpoint == "" {
		return nil, "", errors.New("end point is not set")
	}

	if socketDir == sockdirInvalid {
		return nil, "", errors.New("socket direction is not set")
	}

	if socketType == SocktypeInvalid {
		return nil, "", errors.New("socket type is not set")
	}

	zmq_type := zmq_socket_type(kind, socketType)

	socket, err := zmq.NewSocket(zmq_type)

	if err != nil {
		return nil, "", err
	}

	err = setSocketOptions(socket, zmq_type)
	if err != nil {
		return nil, "", err
	}

	if socketDir == sockdirAccept {
		err = socket.Bind(endpoint)
		if err != nil {
			return nil, "", err
		}
	} else if socketDir == sockdirConnect {
		err = socket.Connect(endpoint)
		if err != nil {
			return nil, "", err
		}
	}

	return socket, endpoint, nil
}

type zmq_io struct {
	sock *zmq.Socket
	ep   string
}

func (i *zmq_io) Read(p []byte) (n int, err error) {
	buf, err := i.sock.RecvBytes(0)
	if err != nil {
		return 0, err
	}
	copy(p, buf)
	return len(buf), nil
}

func (o *zmq_io) Write(p []byte) (int, error) {
	return o.sock.SendBytes(p, 0)
}

func (o *zmq_io) Close() error {
	return o.sock.Close()
}

func (o *zmq_io) Unbind() error {
	return o.sock.Unbind(o.ep)
}

func zmqIO(ep string, kind socketKind) (*zmq_io, error) {
	socket, endpoint, err := zmq_socket(ep, kind)

	if err != nil {
		return nil, err
	}

	return &zmq_io{sock: socket, ep: endpoint}, nil
}

func NewZMQWriter(ep string) (io.WriteCloser, error) {
	return zmqIO(ep, socketOutput)
}

func NewZMQReader(ep string) (io.ReadCloser, error) {
	return zmqIO(ep, socketInput)
}

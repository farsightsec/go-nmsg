package nmsg

import (
	"errors"
	"fmt"
	zmq "github.com/pebbe/zmq4"
	"io"
	"strings"
)

type SocketKind int
type SocketDirection int
type SocketType int

const (
	SocketInput  SocketKind = 0
	SocketOutput            = 1
)
const (
	SockdirInvalid SocketDirection = 0
	SockdirAccept                  = 1
	SockdirConnect                 = 2
)

const (
	SocktypeInvalid  SocketType = 0
	SocktypePubsub              = 1
	SocktypePushpull            = 2
)

func munge_endpoint(ep string) (string, SocketDirection, SocketType, error) {
	endpoint := ""
	sockdir := SockdirInvalid
	socktype := SocktypeInvalid

	tokens := strings.Split(ep, ",")
	for i, tok := range tokens {
		if i == 0 {
			endpoint = tok
		} else {
			switch tok {
			case "accept":
				if sockdir != SockdirInvalid {
					return "", SockdirInvalid, SocktypeInvalid, errors.New("socket direction is already set")
				}
				sockdir = SockdirAccept
			case "connect":
				if sockdir != SockdirInvalid {
					return "", SockdirInvalid, SocktypeInvalid, errors.New("socket direction is already set")
				}
				sockdir = SockdirConnect
			case "pubsub":
				if socktype != SocktypeInvalid {
					return "", SockdirInvalid, SocktypeInvalid, errors.New("socket type is already set")
				}
				socktype = SocktypePubsub
			case "pushpull":
				if socktype != SocktypeInvalid {
					return "", SockdirInvalid, SocktypeInvalid, errors.New("socket type is already set")
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

func zmq_socket_type(kind SocketKind, socketType SocketType) zmq.Type {
	if kind == SocketInput {
		if socketType == SocktypePubsub {
			return zmq.SUB
		} else if socketType == SocktypePushpull {
			return zmq.PULL
		}
	} else if kind == SocketOutput {
		if socketType == SocktypePubsub {
			return zmq.PUB
		} else if socketType == SocktypePushpull {
			return zmq.PUSH
		}
	}

	return zmq.Type(-1)
}

func zmq_socket(ep string, kind SocketKind) (*zmq.Socket, string, error) {
	endpoint, socketDir, socketType, err := munge_endpoint(ep)

	if err != nil {
		return nil, "", err
	}

	if endpoint == "" {
		return nil, "", errors.New("end point is not set")
	}

	if socketDir == SockdirInvalid {
		return nil, "", errors.New("socket direction is not set")
	}

	if socketType == SocktypeInvalid {
		return nil, "", errors.New("socket type is not set")
	}

	if socketType == SocktypePubsub {
		if kind == SocketInput && socketDir == SockdirAccept {
			return nil, "", errors.New("subscriber socket must connect")
		} else if kind == SocketOutput && socketDir == SockdirConnect {
			return nil, "", errors.New("publisher socket must accept")
		}
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

	if socketDir == SockdirAccept {
		err = socket.Bind(endpoint)
		if err != nil {
			return nil, "", err
		}
	} else if socketDir == SockdirConnect {
		err = socket.Connect(endpoint)
		if err != nil {
			return nil, "", err
		}
	}

	return socket, endpoint, nil
}

func Version() string {
	major, minor, patch := zmq.Version()
	return fmt.Sprintf("%d.%d.%d", major, minor, patch)
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

func zmqIO(ep string, kind SocketKind) (*zmq_io, error) {
	socket, endpoint, err := zmq_socket(ep, kind)

	if err != nil {
		return nil, err
	}

	return &zmq_io{sock: socket, ep: endpoint}, nil
}

func ZMQWriter(ep string) (io.Writer, error) {
	return zmqIO(ep, SocketOutput)
}

func ZMQReader(ep string) (io.Reader, error) {
	return zmqIO(ep, SocketInput)
}

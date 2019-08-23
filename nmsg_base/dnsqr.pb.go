// Code generated by protoc-gen-go.
// source: dnsqr.proto
// DO NOT EDIT!

package nmsg_base

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

type DnsQRType int32

const (
	DnsQRType_UDP_INVALID              DnsQRType = 0
	DnsQRType_UDP_QUERY_RESPONSE       DnsQRType = 1
	DnsQRType_UDP_UNANSWERED_QUERY     DnsQRType = 2
	DnsQRType_UDP_UNSOLICITED_RESPONSE DnsQRType = 3
	DnsQRType_TCP                      DnsQRType = 4
	DnsQRType_ICMP                     DnsQRType = 5
	DnsQRType_UDP_QUERY_ONLY           DnsQRType = 6
	DnsQRType_UDP_RESPONSE_ONLY        DnsQRType = 7
)

var DnsQRType_name = map[int32]string{
	0: "UDP_INVALID",
	1: "UDP_QUERY_RESPONSE",
	2: "UDP_UNANSWERED_QUERY",
	3: "UDP_UNSOLICITED_RESPONSE",
	4: "TCP",
	5: "ICMP",
	6: "UDP_QUERY_ONLY",
	7: "UDP_RESPONSE_ONLY",
}
var DnsQRType_value = map[string]int32{
	"UDP_INVALID":              0,
	"UDP_QUERY_RESPONSE":       1,
	"UDP_UNANSWERED_QUERY":     2,
	"UDP_UNSOLICITED_RESPONSE": 3,
	"TCP":                      4,
	"ICMP":                     5,
	"UDP_QUERY_ONLY":           6,
	"UDP_RESPONSE_ONLY":        7,
}

func (x DnsQRType) Enum() *DnsQRType {
	p := new(DnsQRType)
	*p = x
	return p
}
func (x DnsQRType) String() string {
	return proto.EnumName(DnsQRType_name, int32(x))
}
func (x *DnsQRType) UnmarshalJSON(data []byte) error {
	value, err := proto.UnmarshalJSONEnum(DnsQRType_value, data, "DnsQRType")
	if err != nil {
		return err
	}
	*x = DnsQRType(value)
	return nil
}
func (DnsQRType) EnumDescriptor() ([]byte, []int) { return fileDescriptor1, []int{0} }

type UdpChecksum int32

const (
	UdpChecksum_ERROR     UdpChecksum = 0
	UdpChecksum_ABSENT    UdpChecksum = 1
	UdpChecksum_INCORRECT UdpChecksum = 2
	UdpChecksum_CORRECT   UdpChecksum = 3
)

var UdpChecksum_name = map[int32]string{
	0: "ERROR",
	1: "ABSENT",
	2: "INCORRECT",
	3: "CORRECT",
}
var UdpChecksum_value = map[string]int32{
	"ERROR":     0,
	"ABSENT":    1,
	"INCORRECT": 2,
	"CORRECT":   3,
}

func (x UdpChecksum) Enum() *UdpChecksum {
	p := new(UdpChecksum)
	*p = x
	return p
}
func (x UdpChecksum) String() string {
	return proto.EnumName(UdpChecksum_name, int32(x))
}
func (x *UdpChecksum) UnmarshalJSON(data []byte) error {
	value, err := proto.UnmarshalJSONEnum(UdpChecksum_value, data, "UdpChecksum")
	if err != nil {
		return err
	}
	*x = UdpChecksum(value)
	return nil
}
func (UdpChecksum) EnumDescriptor() ([]byte, []int) { return fileDescriptor1, []int{1} }

type DnsQR struct {
	Type                  *DnsQRType   `protobuf:"varint,1,req,name=type,enum=nmsg.base.DnsQRType" json:"type,omitempty"`
	QueryIp               []byte       `protobuf:"bytes,2,req,name=query_ip" json:"query_ip,omitempty"`
	ResponseIp            []byte       `protobuf:"bytes,3,req,name=response_ip" json:"response_ip,omitempty"`
	Proto                 *uint32      `protobuf:"varint,4,req,name=proto" json:"proto,omitempty"`
	QueryPort             *uint32      `protobuf:"varint,5,req,name=query_port" json:"query_port,omitempty"`
	ResponsePort          *uint32      `protobuf:"varint,6,req,name=response_port" json:"response_port,omitempty"`
	Id                    *uint32      `protobuf:"varint,7,req,name=id" json:"id,omitempty"`
	Qname                 []byte       `protobuf:"bytes,8,opt,name=qname" json:"qname,omitempty"`
	Qtype                 *uint32      `protobuf:"varint,9,opt,name=qtype" json:"qtype,omitempty"`
	Qclass                *uint32      `protobuf:"varint,10,opt,name=qclass" json:"qclass,omitempty"`
	Rcode                 *uint32      `protobuf:"varint,11,opt,name=rcode" json:"rcode,omitempty"`
	QueryPacket           [][]byte     `protobuf:"bytes,12,rep,name=query_packet" json:"query_packet,omitempty"`
	QueryTimeSec          []int64      `protobuf:"varint,13,rep,name=query_time_sec" json:"query_time_sec,omitempty"`
	QueryTimeNsec         []int32      `protobuf:"fixed32,14,rep,name=query_time_nsec" json:"query_time_nsec,omitempty"`
	ResponsePacket        [][]byte     `protobuf:"bytes,15,rep,name=response_packet" json:"response_packet,omitempty"`
	ResponseTimeSec       []int64      `protobuf:"varint,16,rep,name=response_time_sec" json:"response_time_sec,omitempty"`
	ResponseTimeNsec      []int32      `protobuf:"fixed32,17,rep,name=response_time_nsec" json:"response_time_nsec,omitempty"`
	Tcp                   []byte       `protobuf:"bytes,18,opt,name=tcp" json:"tcp,omitempty"`
	Icmp                  []byte       `protobuf:"bytes,19,opt,name=icmp" json:"icmp,omitempty"`
	Timeout               *float64     `protobuf:"fixed64,20,opt,name=timeout" json:"timeout,omitempty"`
	UdpChecksum           *UdpChecksum `protobuf:"varint,21,opt,name=udp_checksum,enum=nmsg.base.UdpChecksum" json:"udp_checksum,omitempty"`
	ResolverAddressZeroed *bool        `protobuf:"varint,22,opt,name=resolver_address_zeroed" json:"resolver_address_zeroed,omitempty"`
	XXX_unrecognized      []byte       `json:"-"`
}

func (m *DnsQR) Reset()                    { *m = DnsQR{} }
func (m *DnsQR) String() string            { return proto.CompactTextString(m) }
func (*DnsQR) ProtoMessage()               {}
func (*DnsQR) Descriptor() ([]byte, []int) { return fileDescriptor1, []int{0} }

func (m *DnsQR) GetType() DnsQRType {
	if m != nil && m.Type != nil {
		return *m.Type
	}
	return DnsQRType_UDP_INVALID
}

func (m *DnsQR) GetQueryIp() []byte {
	if m != nil {
		return m.QueryIp
	}
	return nil
}

func (m *DnsQR) GetResponseIp() []byte {
	if m != nil {
		return m.ResponseIp
	}
	return nil
}

func (m *DnsQR) GetProto() uint32 {
	if m != nil && m.Proto != nil {
		return *m.Proto
	}
	return 0
}

func (m *DnsQR) GetQueryPort() uint32 {
	if m != nil && m.QueryPort != nil {
		return *m.QueryPort
	}
	return 0
}

func (m *DnsQR) GetResponsePort() uint32 {
	if m != nil && m.ResponsePort != nil {
		return *m.ResponsePort
	}
	return 0
}

func (m *DnsQR) GetId() uint32 {
	if m != nil && m.Id != nil {
		return *m.Id
	}
	return 0
}

func (m *DnsQR) GetQname() []byte {
	if m != nil {
		return m.Qname
	}
	return nil
}

func (m *DnsQR) GetQtype() uint32 {
	if m != nil && m.Qtype != nil {
		return *m.Qtype
	}
	return 0
}

func (m *DnsQR) GetQclass() uint32 {
	if m != nil && m.Qclass != nil {
		return *m.Qclass
	}
	return 0
}

func (m *DnsQR) GetRcode() uint32 {
	if m != nil && m.Rcode != nil {
		return *m.Rcode
	}
	return 0
}

func (m *DnsQR) GetQueryPacket() [][]byte {
	if m != nil {
		return m.QueryPacket
	}
	return nil
}

func (m *DnsQR) GetQueryTimeSec() []int64 {
	if m != nil {
		return m.QueryTimeSec
	}
	return nil
}

func (m *DnsQR) GetQueryTimeNsec() []int32 {
	if m != nil {
		return m.QueryTimeNsec
	}
	return nil
}

func (m *DnsQR) GetResponsePacket() [][]byte {
	if m != nil {
		return m.ResponsePacket
	}
	return nil
}

func (m *DnsQR) GetResponseTimeSec() []int64 {
	if m != nil {
		return m.ResponseTimeSec
	}
	return nil
}

func (m *DnsQR) GetResponseTimeNsec() []int32 {
	if m != nil {
		return m.ResponseTimeNsec
	}
	return nil
}

func (m *DnsQR) GetTcp() []byte {
	if m != nil {
		return m.Tcp
	}
	return nil
}

func (m *DnsQR) GetIcmp() []byte {
	if m != nil {
		return m.Icmp
	}
	return nil
}

func (m *DnsQR) GetTimeout() float64 {
	if m != nil && m.Timeout != nil {
		return *m.Timeout
	}
	return 0
}

func (m *DnsQR) GetUdpChecksum() UdpChecksum {
	if m != nil && m.UdpChecksum != nil {
		return *m.UdpChecksum
	}
	return UdpChecksum_ERROR
}

func (m *DnsQR) GetResolverAddressZeroed() bool {
	if m != nil && m.ResolverAddressZeroed != nil {
		return *m.ResolverAddressZeroed
	}
	return false
}

func init() {
	proto.RegisterType((*DnsQR)(nil), "nmsg.base.DnsQR")
	proto.RegisterEnum("nmsg.base.DnsQRType", DnsQRType_name, DnsQRType_value)
	proto.RegisterEnum("nmsg.base.UdpChecksum", UdpChecksum_name, UdpChecksum_value)
}

func init() { proto.RegisterFile("dnsqr.proto", fileDescriptor1) }

var fileDescriptor1 = []byte{
	// 491 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0x54, 0x92, 0xdb, 0x6e, 0x9b, 0x40,
	0x10, 0x86, 0x6b, 0xe3, 0xe3, 0x70, 0xf4, 0xc6, 0x71, 0xb6, 0x55, 0xa5, 0x5a, 0xb9, 0xaa, 0xa2,
	0xca, 0x17, 0x79, 0x82, 0xba, 0x98, 0x0b, 0x24, 0x17, 0x1c, 0xc0, 0xad, 0x72, 0x85, 0x28, 0xac,
	0x5a, 0x2b, 0xe1, 0xb8, 0xb8, 0x52, 0xfa, 0x48, 0x7d, 0xb1, 0xbe, 0x46, 0x87, 0x25, 0xc1, 0xce,
	0x1d, 0xf3, 0xfd, 0x33, 0xff, 0xfc, 0xcb, 0x2e, 0xc8, 0x49, 0xc6, 0xcb, 0x6a, 0x55, 0x54, 0x79,
	0x9d, 0x93, 0x69, 0x96, 0xf2, 0x9f, 0xab, 0x1f, 0x11, 0x67, 0xd7, 0xff, 0x24, 0x18, 0x6e, 0x32,
	0x7e, 0xe7, 0x91, 0x6b, 0x18, 0xd4, 0x4f, 0x05, 0xa3, 0xbd, 0x65, 0xff, 0xa3, 0x76, 0x3b, 0x5f,
	0x75, 0x3d, 0x2b, 0xa1, 0x07, 0xa8, 0x11, 0x03, 0x26, 0xe5, 0x91, 0x55, 0x4f, 0xe1, 0xa1, 0xa0,
	0x7d, 0xec, 0x53, 0xc8, 0x05, 0xc8, 0x15, 0xe3, 0x45, 0x9e, 0x71, 0xd6, 0x40, 0x49, 0x40, 0x15,
	0x86, 0x62, 0x11, 0x1d, 0x60, 0xa9, 0x12, 0x02, 0xd0, 0x4e, 0x15, 0x79, 0x55, 0xd3, 0xa1, 0x60,
	0x97, 0xa0, 0x76, 0x73, 0x02, 0x8f, 0x04, 0x06, 0xe8, 0x1f, 0x12, 0x3a, 0x16, 0xdf, 0xe8, 0x52,
	0x66, 0x51, 0xca, 0xe8, 0x64, 0xd9, 0x6b, 0x4d, 0x4b, 0x11, 0x70, 0x8a, 0xa5, 0x4a, 0x34, 0x18,
	0x95, 0xf1, 0x63, 0xc4, 0x39, 0x05, 0x51, 0xa3, 0x5c, 0xc5, 0x79, 0xc2, 0xa8, 0x2c, 0xca, 0x39,
	0x28, 0xcf, 0x3b, 0xa3, 0xf8, 0x81, 0xd5, 0x54, 0x59, 0x4a, 0xe8, 0xb1, 0x00, 0xad, 0xa5, 0xf5,
	0x21, 0x65, 0x21, 0x67, 0x31, 0x55, 0x91, 0x4b, 0xe4, 0x0a, 0xf4, 0x33, 0x9e, 0x35, 0x82, 0x86,
	0x82, 0xde, 0x08, 0xa7, 0x98, 0xad, 0x93, 0x2e, 0x9c, 0xde, 0xc2, 0xac, 0x13, 0x3a, 0x33, 0x43,
	0x98, 0xbd, 0x03, 0xf2, 0x5a, 0x12, 0x7e, 0x33, 0xe1, 0x27, 0x83, 0x54, 0xc7, 0x05, 0x25, 0xe2,
	0x44, 0x0a, 0x0c, 0x0e, 0x71, 0x5a, 0xd0, 0x0b, 0x51, 0xe9, 0x30, 0x6e, 0xba, 0xf3, 0x63, 0x4d,
	0xe7, 0x08, 0x7a, 0xe4, 0x13, 0x28, 0xc7, 0xa4, 0x08, 0xe3, 0x5f, 0x2c, 0x7e, 0xe0, 0xc7, 0x94,
	0x5e, 0x22, 0xd5, 0x6e, 0x17, 0x67, 0x17, 0xb3, 0x4f, 0x0a, 0xf3, 0x59, 0x25, 0x1f, 0xe0, 0x0a,
	0xb7, 0xe6, 0x8f, 0xbf, 0x59, 0x15, 0x46, 0x49, 0x82, 0xdf, 0x3c, 0xfc, 0xc3, 0xaa, 0x9c, 0x25,
	0x74, 0x81, 0x83, 0x93, 0x9b, 0xbf, 0x3d, 0x98, 0x9e, 0x6e, 0x52, 0x07, 0x79, 0xbf, 0xd9, 0x85,
	0xb6, 0xf3, 0x6d, 0xbd, 0xb5, 0x37, 0xc6, 0x1b, 0xfc, 0x35, 0xa4, 0x01, 0x77, 0x7b, 0xcb, 0xbb,
	0x0f, 0x3d, 0xcb, 0xdf, 0xb9, 0x8e, 0x6f, 0x19, 0x3d, 0x42, 0x61, 0xde, 0xf0, 0xbd, 0xb3, 0x76,
	0xfc, 0xef, 0x96, 0x67, 0x6d, 0xda, 0x16, 0xa3, 0x4f, 0xde, 0x03, 0x6d, 0x15, 0xdf, 0xdd, 0xda,
	0xa6, 0x1d, 0xa0, 0xd4, 0xcd, 0x49, 0x64, 0x0c, 0x52, 0x60, 0xee, 0x8c, 0x01, 0x99, 0xc0, 0xc0,
	0x36, 0xbf, 0xee, 0x8c, 0x21, 0xbe, 0x03, 0xed, 0xb4, 0xc2, 0x75, 0xb6, 0xf7, 0xc6, 0x08, 0xdf,
	0xc1, 0xac, 0x61, 0x2f, 0x83, 0x2d, 0x1e, 0xdf, 0x7c, 0xc6, 0x78, 0x67, 0x87, 0x9b, 0xc2, 0xd0,
	0xf2, 0x3c, 0xd7, 0xc3, 0x9c, 0x00, 0xa3, 0xf5, 0x17, 0xdf, 0x72, 0x02, 0xcc, 0xa6, 0xc2, 0xd4,
	0x76, 0x4c, 0xd7, 0xf3, 0x2c, 0x33, 0xc0, 0x40, 0x32, 0x8c, 0x5f, 0x0a, 0xe9, 0x7f, 0x00, 0x00,
	0x00, 0xff, 0xff, 0x04, 0x82, 0x9b, 0xdb, 0xf1, 0x02, 0x00, 0x00,
}

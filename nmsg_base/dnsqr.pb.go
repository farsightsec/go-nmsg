// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0-devel
// 	protoc        (unknown)
// source: dnsqr.proto

package nmsg_base

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

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

// Enum value maps for DnsQRType.
var (
	DnsQRType_name = map[int32]string{
		0: "UDP_INVALID",
		1: "UDP_QUERY_RESPONSE",
		2: "UDP_UNANSWERED_QUERY",
		3: "UDP_UNSOLICITED_RESPONSE",
		4: "TCP",
		5: "ICMP",
		6: "UDP_QUERY_ONLY",
		7: "UDP_RESPONSE_ONLY",
	}
	DnsQRType_value = map[string]int32{
		"UDP_INVALID":              0,
		"UDP_QUERY_RESPONSE":       1,
		"UDP_UNANSWERED_QUERY":     2,
		"UDP_UNSOLICITED_RESPONSE": 3,
		"TCP":                      4,
		"ICMP":                     5,
		"UDP_QUERY_ONLY":           6,
		"UDP_RESPONSE_ONLY":        7,
	}
)

func (x DnsQRType) Enum() *DnsQRType {
	p := new(DnsQRType)
	*p = x
	return p
}

func (x DnsQRType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (DnsQRType) Descriptor() protoreflect.EnumDescriptor {
	return file_dnsqr_proto_enumTypes[0].Descriptor()
}

func (DnsQRType) Type() protoreflect.EnumType {
	return &file_dnsqr_proto_enumTypes[0]
}

func (x DnsQRType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Do not use.
func (x *DnsQRType) UnmarshalJSON(b []byte) error {
	num, err := protoimpl.X.UnmarshalJSONEnum(x.Descriptor(), b)
	if err != nil {
		return err
	}
	*x = DnsQRType(num)
	return nil
}

// Deprecated: Use DnsQRType.Descriptor instead.
func (DnsQRType) EnumDescriptor() ([]byte, []int) {
	return file_dnsqr_proto_rawDescGZIP(), []int{0}
}

type UdpChecksum int32

const (
	UdpChecksum_ERROR     UdpChecksum = 0
	UdpChecksum_ABSENT    UdpChecksum = 1
	UdpChecksum_INCORRECT UdpChecksum = 2
	UdpChecksum_CORRECT   UdpChecksum = 3
)

// Enum value maps for UdpChecksum.
var (
	UdpChecksum_name = map[int32]string{
		0: "ERROR",
		1: "ABSENT",
		2: "INCORRECT",
		3: "CORRECT",
	}
	UdpChecksum_value = map[string]int32{
		"ERROR":     0,
		"ABSENT":    1,
		"INCORRECT": 2,
		"CORRECT":   3,
	}
)

func (x UdpChecksum) Enum() *UdpChecksum {
	p := new(UdpChecksum)
	*p = x
	return p
}

func (x UdpChecksum) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (UdpChecksum) Descriptor() protoreflect.EnumDescriptor {
	return file_dnsqr_proto_enumTypes[1].Descriptor()
}

func (UdpChecksum) Type() protoreflect.EnumType {
	return &file_dnsqr_proto_enumTypes[1]
}

func (x UdpChecksum) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Do not use.
func (x *UdpChecksum) UnmarshalJSON(b []byte) error {
	num, err := protoimpl.X.UnmarshalJSONEnum(x.Descriptor(), b)
	if err != nil {
		return err
	}
	*x = UdpChecksum(num)
	return nil
}

// Deprecated: Use UdpChecksum.Descriptor instead.
func (UdpChecksum) EnumDescriptor() ([]byte, []int) {
	return file_dnsqr_proto_rawDescGZIP(), []int{1}
}

type DnsQR struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Type                  *DnsQRType   `protobuf:"varint,1,req,name=type,enum=nmsg.base.DnsQRType" json:"type,omitempty"`
	QueryIp               []byte       `protobuf:"bytes,2,req,name=query_ip,json=queryIp" json:"query_ip,omitempty"`
	ResponseIp            []byte       `protobuf:"bytes,3,req,name=response_ip,json=responseIp" json:"response_ip,omitempty"`
	Proto                 *uint32      `protobuf:"varint,4,req,name=proto" json:"proto,omitempty"`
	QueryPort             *uint32      `protobuf:"varint,5,req,name=query_port,json=queryPort" json:"query_port,omitempty"`
	ResponsePort          *uint32      `protobuf:"varint,6,req,name=response_port,json=responsePort" json:"response_port,omitempty"`
	Id                    *uint32      `protobuf:"varint,7,req,name=id" json:"id,omitempty"`
	Qname                 []byte       `protobuf:"bytes,8,opt,name=qname" json:"qname,omitempty"`
	Qtype                 *uint32      `protobuf:"varint,9,opt,name=qtype" json:"qtype,omitempty"`
	Qclass                *uint32      `protobuf:"varint,10,opt,name=qclass" json:"qclass,omitempty"`
	Rcode                 *uint32      `protobuf:"varint,11,opt,name=rcode" json:"rcode,omitempty"`
	QueryPacket           [][]byte     `protobuf:"bytes,12,rep,name=query_packet,json=queryPacket" json:"query_packet,omitempty"`
	QueryTimeSec          []int64      `protobuf:"varint,13,rep,name=query_time_sec,json=queryTimeSec" json:"query_time_sec,omitempty"`
	QueryTimeNsec         []int32      `protobuf:"fixed32,14,rep,name=query_time_nsec,json=queryTimeNsec" json:"query_time_nsec,omitempty"`
	ResponsePacket        [][]byte     `protobuf:"bytes,15,rep,name=response_packet,json=responsePacket" json:"response_packet,omitempty"`
	ResponseTimeSec       []int64      `protobuf:"varint,16,rep,name=response_time_sec,json=responseTimeSec" json:"response_time_sec,omitempty"`
	ResponseTimeNsec      []int32      `protobuf:"fixed32,17,rep,name=response_time_nsec,json=responseTimeNsec" json:"response_time_nsec,omitempty"`
	Tcp                   []byte       `protobuf:"bytes,18,opt,name=tcp" json:"tcp,omitempty"`
	Icmp                  []byte       `protobuf:"bytes,19,opt,name=icmp" json:"icmp,omitempty"`
	Timeout               *float64     `protobuf:"fixed64,20,opt,name=timeout" json:"timeout,omitempty"`
	UdpChecksum           *UdpChecksum `protobuf:"varint,21,opt,name=udp_checksum,json=udpChecksum,enum=nmsg.base.UdpChecksum" json:"udp_checksum,omitempty"`
	ResolverAddressZeroed *bool        `protobuf:"varint,22,opt,name=resolver_address_zeroed,json=resolverAddressZeroed" json:"resolver_address_zeroed,omitempty"`
}

func (x *DnsQR) Reset() {
	*x = DnsQR{}
	if protoimpl.UnsafeEnabled {
		mi := &file_dnsqr_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DnsQR) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DnsQR) ProtoMessage() {}

func (x *DnsQR) ProtoReflect() protoreflect.Message {
	mi := &file_dnsqr_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DnsQR.ProtoReflect.Descriptor instead.
func (*DnsQR) Descriptor() ([]byte, []int) {
	return file_dnsqr_proto_rawDescGZIP(), []int{0}
}

func (x *DnsQR) GetType() DnsQRType {
	if x != nil && x.Type != nil {
		return *x.Type
	}
	return DnsQRType_UDP_INVALID
}

func (x *DnsQR) GetQueryIp() []byte {
	if x != nil {
		return x.QueryIp
	}
	return nil
}

func (x *DnsQR) GetResponseIp() []byte {
	if x != nil {
		return x.ResponseIp
	}
	return nil
}

func (x *DnsQR) GetProto() uint32 {
	if x != nil && x.Proto != nil {
		return *x.Proto
	}
	return 0
}

func (x *DnsQR) GetQueryPort() uint32 {
	if x != nil && x.QueryPort != nil {
		return *x.QueryPort
	}
	return 0
}

func (x *DnsQR) GetResponsePort() uint32 {
	if x != nil && x.ResponsePort != nil {
		return *x.ResponsePort
	}
	return 0
}

func (x *DnsQR) GetId() uint32 {
	if x != nil && x.Id != nil {
		return *x.Id
	}
	return 0
}

func (x *DnsQR) GetQname() []byte {
	if x != nil {
		return x.Qname
	}
	return nil
}

func (x *DnsQR) GetQtype() uint32 {
	if x != nil && x.Qtype != nil {
		return *x.Qtype
	}
	return 0
}

func (x *DnsQR) GetQclass() uint32 {
	if x != nil && x.Qclass != nil {
		return *x.Qclass
	}
	return 0
}

func (x *DnsQR) GetRcode() uint32 {
	if x != nil && x.Rcode != nil {
		return *x.Rcode
	}
	return 0
}

func (x *DnsQR) GetQueryPacket() [][]byte {
	if x != nil {
		return x.QueryPacket
	}
	return nil
}

func (x *DnsQR) GetQueryTimeSec() []int64 {
	if x != nil {
		return x.QueryTimeSec
	}
	return nil
}

func (x *DnsQR) GetQueryTimeNsec() []int32 {
	if x != nil {
		return x.QueryTimeNsec
	}
	return nil
}

func (x *DnsQR) GetResponsePacket() [][]byte {
	if x != nil {
		return x.ResponsePacket
	}
	return nil
}

func (x *DnsQR) GetResponseTimeSec() []int64 {
	if x != nil {
		return x.ResponseTimeSec
	}
	return nil
}

func (x *DnsQR) GetResponseTimeNsec() []int32 {
	if x != nil {
		return x.ResponseTimeNsec
	}
	return nil
}

func (x *DnsQR) GetTcp() []byte {
	if x != nil {
		return x.Tcp
	}
	return nil
}

func (x *DnsQR) GetIcmp() []byte {
	if x != nil {
		return x.Icmp
	}
	return nil
}

func (x *DnsQR) GetTimeout() float64 {
	if x != nil && x.Timeout != nil {
		return *x.Timeout
	}
	return 0
}

func (x *DnsQR) GetUdpChecksum() UdpChecksum {
	if x != nil && x.UdpChecksum != nil {
		return *x.UdpChecksum
	}
	return UdpChecksum_ERROR
}

func (x *DnsQR) GetResolverAddressZeroed() bool {
	if x != nil && x.ResolverAddressZeroed != nil {
		return *x.ResolverAddressZeroed
	}
	return false
}

var File_dnsqr_proto protoreflect.FileDescriptor

var file_dnsqr_proto_rawDesc = []byte{
	0x0a, 0x0b, 0x64, 0x6e, 0x73, 0x71, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x09, 0x6e,
	0x6d, 0x73, 0x67, 0x2e, 0x62, 0x61, 0x73, 0x65, 0x22, 0xd8, 0x05, 0x0a, 0x05, 0x44, 0x6e, 0x73,
	0x51, 0x52, 0x12, 0x28, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20, 0x02, 0x28, 0x0e,
	0x32, 0x14, 0x2e, 0x6e, 0x6d, 0x73, 0x67, 0x2e, 0x62, 0x61, 0x73, 0x65, 0x2e, 0x44, 0x6e, 0x73,
	0x51, 0x52, 0x54, 0x79, 0x70, 0x65, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x19, 0x0a, 0x08,
	0x71, 0x75, 0x65, 0x72, 0x79, 0x5f, 0x69, 0x70, 0x18, 0x02, 0x20, 0x02, 0x28, 0x0c, 0x52, 0x07,
	0x71, 0x75, 0x65, 0x72, 0x79, 0x49, 0x70, 0x12, 0x1f, 0x0a, 0x0b, 0x72, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x5f, 0x69, 0x70, 0x18, 0x03, 0x20, 0x02, 0x28, 0x0c, 0x52, 0x0a, 0x72, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x49, 0x70, 0x12, 0x14, 0x0a, 0x05, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x18, 0x04, 0x20, 0x02, 0x28, 0x0d, 0x52, 0x05, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1d,
	0x0a, 0x0a, 0x71, 0x75, 0x65, 0x72, 0x79, 0x5f, 0x70, 0x6f, 0x72, 0x74, 0x18, 0x05, 0x20, 0x02,
	0x28, 0x0d, 0x52, 0x09, 0x71, 0x75, 0x65, 0x72, 0x79, 0x50, 0x6f, 0x72, 0x74, 0x12, 0x23, 0x0a,
	0x0d, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x5f, 0x70, 0x6f, 0x72, 0x74, 0x18, 0x06,
	0x20, 0x02, 0x28, 0x0d, 0x52, 0x0c, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x50, 0x6f,
	0x72, 0x74, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x07, 0x20, 0x02, 0x28, 0x0d, 0x52, 0x02,
	0x69, 0x64, 0x12, 0x14, 0x0a, 0x05, 0x71, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x08, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x05, 0x71, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x71, 0x74, 0x79, 0x70,
	0x65, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x71, 0x74, 0x79, 0x70, 0x65, 0x12, 0x16,
	0x0a, 0x06, 0x71, 0x63, 0x6c, 0x61, 0x73, 0x73, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x06,
	0x71, 0x63, 0x6c, 0x61, 0x73, 0x73, 0x12, 0x14, 0x0a, 0x05, 0x72, 0x63, 0x6f, 0x64, 0x65, 0x18,
	0x0b, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x72, 0x63, 0x6f, 0x64, 0x65, 0x12, 0x21, 0x0a, 0x0c,
	0x71, 0x75, 0x65, 0x72, 0x79, 0x5f, 0x70, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x18, 0x0c, 0x20, 0x03,
	0x28, 0x0c, 0x52, 0x0b, 0x71, 0x75, 0x65, 0x72, 0x79, 0x50, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x12,
	0x24, 0x0a, 0x0e, 0x71, 0x75, 0x65, 0x72, 0x79, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x5f, 0x73, 0x65,
	0x63, 0x18, 0x0d, 0x20, 0x03, 0x28, 0x03, 0x52, 0x0c, 0x71, 0x75, 0x65, 0x72, 0x79, 0x54, 0x69,
	0x6d, 0x65, 0x53, 0x65, 0x63, 0x12, 0x26, 0x0a, 0x0f, 0x71, 0x75, 0x65, 0x72, 0x79, 0x5f, 0x74,
	0x69, 0x6d, 0x65, 0x5f, 0x6e, 0x73, 0x65, 0x63, 0x18, 0x0e, 0x20, 0x03, 0x28, 0x0f, 0x52, 0x0d,
	0x71, 0x75, 0x65, 0x72, 0x79, 0x54, 0x69, 0x6d, 0x65, 0x4e, 0x73, 0x65, 0x63, 0x12, 0x27, 0x0a,
	0x0f, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x5f, 0x70, 0x61, 0x63, 0x6b, 0x65, 0x74,
	0x18, 0x0f, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x0e, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x50, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x12, 0x2a, 0x0a, 0x11, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x5f, 0x73, 0x65, 0x63, 0x18, 0x10, 0x20, 0x03, 0x28,
	0x03, 0x52, 0x0f, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x53,
	0x65, 0x63, 0x12, 0x2c, 0x0a, 0x12, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x5f, 0x74,
	0x69, 0x6d, 0x65, 0x5f, 0x6e, 0x73, 0x65, 0x63, 0x18, 0x11, 0x20, 0x03, 0x28, 0x0f, 0x52, 0x10,
	0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x4e, 0x73, 0x65, 0x63,
	0x12, 0x10, 0x0a, 0x03, 0x74, 0x63, 0x70, 0x18, 0x12, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x03, 0x74,
	0x63, 0x70, 0x12, 0x12, 0x0a, 0x04, 0x69, 0x63, 0x6d, 0x70, 0x18, 0x13, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x04, 0x69, 0x63, 0x6d, 0x70, 0x12, 0x18, 0x0a, 0x07, 0x74, 0x69, 0x6d, 0x65, 0x6f, 0x75,
	0x74, 0x18, 0x14, 0x20, 0x01, 0x28, 0x01, 0x52, 0x07, 0x74, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74,
	0x12, 0x39, 0x0a, 0x0c, 0x75, 0x64, 0x70, 0x5f, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x73, 0x75, 0x6d,
	0x18, 0x15, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x16, 0x2e, 0x6e, 0x6d, 0x73, 0x67, 0x2e, 0x62, 0x61,
	0x73, 0x65, 0x2e, 0x55, 0x64, 0x70, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x73, 0x75, 0x6d, 0x52, 0x0b,
	0x75, 0x64, 0x70, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x73, 0x75, 0x6d, 0x12, 0x36, 0x0a, 0x17, 0x72,
	0x65, 0x73, 0x6f, 0x6c, 0x76, 0x65, 0x72, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x5f,
	0x7a, 0x65, 0x72, 0x6f, 0x65, 0x64, 0x18, 0x16, 0x20, 0x01, 0x28, 0x08, 0x52, 0x15, 0x72, 0x65,
	0x73, 0x6f, 0x6c, 0x76, 0x65, 0x72, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x5a, 0x65, 0x72,
	0x6f, 0x65, 0x64, 0x2a, 0xaa, 0x01, 0x0a, 0x09, 0x44, 0x6e, 0x73, 0x51, 0x52, 0x54, 0x79, 0x70,
	0x65, 0x12, 0x0f, 0x0a, 0x0b, 0x55, 0x44, 0x50, 0x5f, 0x49, 0x4e, 0x56, 0x41, 0x4c, 0x49, 0x44,
	0x10, 0x00, 0x12, 0x16, 0x0a, 0x12, 0x55, 0x44, 0x50, 0x5f, 0x51, 0x55, 0x45, 0x52, 0x59, 0x5f,
	0x52, 0x45, 0x53, 0x50, 0x4f, 0x4e, 0x53, 0x45, 0x10, 0x01, 0x12, 0x18, 0x0a, 0x14, 0x55, 0x44,
	0x50, 0x5f, 0x55, 0x4e, 0x41, 0x4e, 0x53, 0x57, 0x45, 0x52, 0x45, 0x44, 0x5f, 0x51, 0x55, 0x45,
	0x52, 0x59, 0x10, 0x02, 0x12, 0x1c, 0x0a, 0x18, 0x55, 0x44, 0x50, 0x5f, 0x55, 0x4e, 0x53, 0x4f,
	0x4c, 0x49, 0x43, 0x49, 0x54, 0x45, 0x44, 0x5f, 0x52, 0x45, 0x53, 0x50, 0x4f, 0x4e, 0x53, 0x45,
	0x10, 0x03, 0x12, 0x07, 0x0a, 0x03, 0x54, 0x43, 0x50, 0x10, 0x04, 0x12, 0x08, 0x0a, 0x04, 0x49,
	0x43, 0x4d, 0x50, 0x10, 0x05, 0x12, 0x12, 0x0a, 0x0e, 0x55, 0x44, 0x50, 0x5f, 0x51, 0x55, 0x45,
	0x52, 0x59, 0x5f, 0x4f, 0x4e, 0x4c, 0x59, 0x10, 0x06, 0x12, 0x15, 0x0a, 0x11, 0x55, 0x44, 0x50,
	0x5f, 0x52, 0x45, 0x53, 0x50, 0x4f, 0x4e, 0x53, 0x45, 0x5f, 0x4f, 0x4e, 0x4c, 0x59, 0x10, 0x07,
	0x2a, 0x40, 0x0a, 0x0b, 0x55, 0x64, 0x70, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x73, 0x75, 0x6d, 0x12,
	0x09, 0x0a, 0x05, 0x45, 0x52, 0x52, 0x4f, 0x52, 0x10, 0x00, 0x12, 0x0a, 0x0a, 0x06, 0x41, 0x42,
	0x53, 0x45, 0x4e, 0x54, 0x10, 0x01, 0x12, 0x0d, 0x0a, 0x09, 0x49, 0x4e, 0x43, 0x4f, 0x52, 0x52,
	0x45, 0x43, 0x54, 0x10, 0x02, 0x12, 0x0b, 0x0a, 0x07, 0x43, 0x4f, 0x52, 0x52, 0x45, 0x43, 0x54,
	0x10, 0x03, 0x42, 0x34, 0x5a, 0x32, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x66, 0x61, 0x72, 0x73, 0x69, 0x67, 0x68, 0x74, 0x73, 0x65, 0x63, 0x2f, 0x67, 0x6f, 0x2d,
	0x6e, 0x6d, 0x73, 0x67, 0x2f, 0x6e, 0x6d, 0x73, 0x67, 0x5f, 0x62, 0x61, 0x73, 0x65, 0x3b, 0x6e,
	0x6d, 0x73, 0x67, 0x5f, 0x62, 0x61, 0x73, 0x65,
}

var (
	file_dnsqr_proto_rawDescOnce sync.Once
	file_dnsqr_proto_rawDescData = file_dnsqr_proto_rawDesc
)

func file_dnsqr_proto_rawDescGZIP() []byte {
	file_dnsqr_proto_rawDescOnce.Do(func() {
		file_dnsqr_proto_rawDescData = protoimpl.X.CompressGZIP(file_dnsqr_proto_rawDescData)
	})
	return file_dnsqr_proto_rawDescData
}

var file_dnsqr_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
var file_dnsqr_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_dnsqr_proto_goTypes = []interface{}{
	(DnsQRType)(0),   // 0: nmsg.base.DnsQRType
	(UdpChecksum)(0), // 1: nmsg.base.UdpChecksum
	(*DnsQR)(nil),    // 2: nmsg.base.DnsQR
}
var file_dnsqr_proto_depIdxs = []int32{
	0, // 0: nmsg.base.DnsQR.type:type_name -> nmsg.base.DnsQRType
	1, // 1: nmsg.base.DnsQR.udp_checksum:type_name -> nmsg.base.UdpChecksum
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_dnsqr_proto_init() }
func file_dnsqr_proto_init() {
	if File_dnsqr_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_dnsqr_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DnsQR); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_dnsqr_proto_rawDesc,
			NumEnums:      2,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_dnsqr_proto_goTypes,
		DependencyIndexes: file_dnsqr_proto_depIdxs,
		EnumInfos:         file_dnsqr_proto_enumTypes,
		MessageInfos:      file_dnsqr_proto_msgTypes,
	}.Build()
	File_dnsqr_proto = out.File
	file_dnsqr_proto_rawDesc = nil
	file_dnsqr_proto_goTypes = nil
	file_dnsqr_proto_depIdxs = nil
}

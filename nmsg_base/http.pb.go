// Code generated by protoc-gen-go.
// source: http.proto
// DO NOT EDIT!

package nmsg_base

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

type HttpType int32

const (
	// unknown = 0;
	HttpType_sinkhole HttpType = 1
)

var HttpType_name = map[int32]string{
	1: "sinkhole",
}
var HttpType_value = map[string]int32{
	"sinkhole": 1,
}

func (x HttpType) Enum() *HttpType {
	p := new(HttpType)
	*p = x
	return p
}
func (x HttpType) String() string {
	return proto.EnumName(HttpType_name, int32(x))
}
func (x *HttpType) UnmarshalJSON(data []byte) error {
	value, err := proto.UnmarshalJSONEnum(HttpType_value, data, "HttpType")
	if err != nil {
		return err
	}
	*x = HttpType(value)
	return nil
}
func (HttpType) EnumDescriptor() ([]byte, []int) { return fileDescriptor4, []int{0} }

type Http struct {
	Type             *HttpType `protobuf:"varint,1,req,name=type,enum=nmsg.base.HttpType" json:"type,omitempty"`
	Srcip            []byte    `protobuf:"bytes,2,opt,name=srcip" json:"srcip,omitempty"`
	Srchost          []byte    `protobuf:"bytes,3,opt,name=srchost" json:"srchost,omitempty"`
	Srcport          *uint32   `protobuf:"varint,4,opt,name=srcport" json:"srcport,omitempty"`
	Dstip            []byte    `protobuf:"bytes,5,opt,name=dstip" json:"dstip,omitempty"`
	Dstport          *uint32   `protobuf:"varint,6,opt,name=dstport" json:"dstport,omitempty"`
	Request          []byte    `protobuf:"bytes,7,opt,name=request" json:"request,omitempty"`
	P0FGenre         []byte    `protobuf:"bytes,65,opt,name=p0f_genre" json:"p0f_genre,omitempty"`
	P0FDetail        []byte    `protobuf:"bytes,66,opt,name=p0f_detail" json:"p0f_detail,omitempty"`
	P0FDist          *int32    `protobuf:"varint,67,opt,name=p0f_dist" json:"p0f_dist,omitempty"`
	P0FLink          []byte    `protobuf:"bytes,68,opt,name=p0f_link" json:"p0f_link,omitempty"`
	P0FTos           []byte    `protobuf:"bytes,69,opt,name=p0f_tos" json:"p0f_tos,omitempty"`
	P0FFw            *uint32   `protobuf:"varint,70,opt,name=p0f_fw" json:"p0f_fw,omitempty"`
	P0FNat           *uint32   `protobuf:"varint,71,opt,name=p0f_nat" json:"p0f_nat,omitempty"`
	P0FReal          *uint32   `protobuf:"varint,72,opt,name=p0f_real" json:"p0f_real,omitempty"`
	P0FScore         *int32    `protobuf:"varint,73,opt,name=p0f_score" json:"p0f_score,omitempty"`
	P0FMflags        *uint32   `protobuf:"varint,74,opt,name=p0f_mflags" json:"p0f_mflags,omitempty"`
	P0FUptime        *int32    `protobuf:"varint,75,opt,name=p0f_uptime" json:"p0f_uptime,omitempty"`
	XXX_unrecognized []byte    `json:"-"`
}

func (m *Http) Reset()                    { *m = Http{} }
func (m *Http) String() string            { return proto.CompactTextString(m) }
func (*Http) ProtoMessage()               {}
func (*Http) Descriptor() ([]byte, []int) { return fileDescriptor4, []int{0} }

func (m *Http) GetType() HttpType {
	if m != nil && m.Type != nil {
		return *m.Type
	}
	return HttpType_sinkhole
}

func (m *Http) GetSrcip() []byte {
	if m != nil {
		return m.Srcip
	}
	return nil
}

func (m *Http) GetSrchost() []byte {
	if m != nil {
		return m.Srchost
	}
	return nil
}

func (m *Http) GetSrcport() uint32 {
	if m != nil && m.Srcport != nil {
		return *m.Srcport
	}
	return 0
}

func (m *Http) GetDstip() []byte {
	if m != nil {
		return m.Dstip
	}
	return nil
}

func (m *Http) GetDstport() uint32 {
	if m != nil && m.Dstport != nil {
		return *m.Dstport
	}
	return 0
}

func (m *Http) GetRequest() []byte {
	if m != nil {
		return m.Request
	}
	return nil
}

func (m *Http) GetP0FGenre() []byte {
	if m != nil {
		return m.P0FGenre
	}
	return nil
}

func (m *Http) GetP0FDetail() []byte {
	if m != nil {
		return m.P0FDetail
	}
	return nil
}

func (m *Http) GetP0FDist() int32 {
	if m != nil && m.P0FDist != nil {
		return *m.P0FDist
	}
	return 0
}

func (m *Http) GetP0FLink() []byte {
	if m != nil {
		return m.P0FLink
	}
	return nil
}

func (m *Http) GetP0FTos() []byte {
	if m != nil {
		return m.P0FTos
	}
	return nil
}

func (m *Http) GetP0FFw() uint32 {
	if m != nil && m.P0FFw != nil {
		return *m.P0FFw
	}
	return 0
}

func (m *Http) GetP0FNat() uint32 {
	if m != nil && m.P0FNat != nil {
		return *m.P0FNat
	}
	return 0
}

func (m *Http) GetP0FReal() uint32 {
	if m != nil && m.P0FReal != nil {
		return *m.P0FReal
	}
	return 0
}

func (m *Http) GetP0FScore() int32 {
	if m != nil && m.P0FScore != nil {
		return *m.P0FScore
	}
	return 0
}

func (m *Http) GetP0FMflags() uint32 {
	if m != nil && m.P0FMflags != nil {
		return *m.P0FMflags
	}
	return 0
}

func (m *Http) GetP0FUptime() int32 {
	if m != nil && m.P0FUptime != nil {
		return *m.P0FUptime
	}
	return 0
}

func init() {
	proto.RegisterType((*Http)(nil), "nmsg.base.Http")
	proto.RegisterEnum("nmsg.base.HttpType", HttpType_name, HttpType_value)
}

func init() { proto.RegisterFile("http.proto", fileDescriptor4) }

var fileDescriptor4 = []byte{
	// 268 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0x4c, 0xd0, 0x4d, 0x4f, 0xf3, 0x30,
	0x0c, 0x07, 0x70, 0xb5, 0x4f, 0xbb, 0x75, 0xd6, 0xb6, 0x67, 0x94, 0x8b, 0x8f, 0x83, 0xd3, 0xc4,
	0xa1, 0x42, 0x7c, 0x03, 0xde, 0x07, 0x5c, 0xb9, 0xa3, 0xb2, 0xa5, 0x2f, 0x22, 0x6d, 0x42, 0xe2,
	0x09, 0xf1, 0x41, 0xf9, 0x3e, 0x38, 0x56, 0x3b, 0x71, 0xf4, 0xef, 0x6f, 0xc7, 0x56, 0x00, 0x1a,
	0x22, 0x5b, 0x58, 0x67, 0xc8, 0xe4, 0xb3, 0xbe, 0xf3, 0x75, 0xf1, 0x5e, 0x7a, 0x75, 0xfe, 0x13,
	0x43, 0xb2, 0xe5, 0x24, 0x3f, 0x83, 0x84, 0xbe, 0xad, 0xc2, 0x68, 0x1d, 0x6f, 0x96, 0x57, 0xa7,
	0xc5, 0xb1, 0xa5, 0x08, 0xf1, 0x2b, 0x47, 0xf9, 0x02, 0x52, 0xef, 0x76, 0xad, 0xc5, 0x78, 0x1d,
	0x6d, 0xe6, 0xf9, 0x7f, 0x98, 0x72, 0xd9, 0x18, 0x4f, 0xf8, 0xef, 0x0f, 0x58, 0xe3, 0x08, 0x13,
	0x86, 0x45, 0x18, 0xd8, 0x7b, 0xe2, 0x81, 0x74, 0xcc, 0xb9, 0x94, 0x7c, 0x22, 0x39, 0x83, 0x53,
	0x9f, 0x07, 0xc5, 0x2f, 0x4c, 0xa5, 0xe3, 0x04, 0x66, 0xf6, 0xb2, 0x7a, 0xab, 0x55, 0xef, 0x14,
	0x5e, 0x0b, 0xe5, 0x00, 0x81, 0xf6, 0x8a, 0xca, 0x56, 0xe3, 0x8d, 0xd8, 0x0a, 0x32, 0xb1, 0x96,
	0x07, 0x6f, 0x59, 0xd2, 0x51, 0x74, 0xdb, 0x7f, 0xe0, 0xdd, 0xb8, 0x2c, 0x08, 0x19, 0x8f, 0xf7,
	0x02, 0x4b, 0x98, 0x04, 0xa8, 0xbe, 0xf0, 0x61, 0x5c, 0x1e, 0xea, 0xbe, 0x24, 0x7c, 0x14, 0x18,
	0xde, 0x70, 0xaa, 0xd4, 0xb8, 0x15, 0x19, 0xce, 0xf1, 0x3b, 0xc3, 0xe7, 0x3c, 0xc9, 0xa2, 0xe1,
	0x9c, 0xae, 0xd2, 0x65, 0xed, 0xf1, 0x59, 0xda, 0x06, 0x3b, 0x58, 0x6a, 0x3b, 0x85, 0x2f, 0xa1,
	0xef, 0x02, 0x21, 0x3b, 0xfe, 0xdb, 0x1c, 0x32, 0xcf, 0x87, 0x35, 0x46, 0xab, 0x55, 0xf4, 0x1b,
	0x00, 0x00, 0xff, 0xff, 0xa3, 0x64, 0x11, 0x56, 0x89, 0x01, 0x00, 0x00,
}

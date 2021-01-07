// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0-devel
// 	protoc        (unknown)
// source: http.proto

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

type HttpType int32

const (
	// unknown = 0;
	HttpType_sinkhole HttpType = 1
)

// Enum value maps for HttpType.
var (
	HttpType_name = map[int32]string{
		1: "sinkhole",
	}
	HttpType_value = map[string]int32{
		"sinkhole": 1,
	}
)

func (x HttpType) Enum() *HttpType {
	p := new(HttpType)
	*p = x
	return p
}

func (x HttpType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (HttpType) Descriptor() protoreflect.EnumDescriptor {
	return file_http_proto_enumTypes[0].Descriptor()
}

func (HttpType) Type() protoreflect.EnumType {
	return &file_http_proto_enumTypes[0]
}

func (x HttpType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Do not use.
func (x *HttpType) UnmarshalJSON(b []byte) error {
	num, err := protoimpl.X.UnmarshalJSONEnum(x.Descriptor(), b)
	if err != nil {
		return err
	}
	*x = HttpType(num)
	return nil
}

// Deprecated: Use HttpType.Descriptor instead.
func (HttpType) EnumDescriptor() ([]byte, []int) {
	return file_http_proto_rawDescGZIP(), []int{0}
}

type Http struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Type      *HttpType `protobuf:"varint,1,req,name=type,enum=nmsg.base.HttpType" json:"type,omitempty"`
	Srcip     []byte    `protobuf:"bytes,2,opt,name=srcip" json:"srcip,omitempty"`
	Srchost   []byte    `protobuf:"bytes,3,opt,name=srchost" json:"srchost,omitempty"`
	Srcport   *uint32   `protobuf:"varint,4,opt,name=srcport" json:"srcport,omitempty"`
	Dstip     []byte    `protobuf:"bytes,5,opt,name=dstip" json:"dstip,omitempty"`
	Dstport   *uint32   `protobuf:"varint,6,opt,name=dstport" json:"dstport,omitempty"`
	Request   []byte    `protobuf:"bytes,7,opt,name=request" json:"request,omitempty"`
	P0FGenre  []byte    `protobuf:"bytes,65,opt,name=p0f_genre,json=p0fGenre" json:"p0f_genre,omitempty"`
	P0FDetail []byte    `protobuf:"bytes,66,opt,name=p0f_detail,json=p0fDetail" json:"p0f_detail,omitempty"`
	P0FDist   *int32    `protobuf:"varint,67,opt,name=p0f_dist,json=p0fDist" json:"p0f_dist,omitempty"`
	P0FLink   []byte    `protobuf:"bytes,68,opt,name=p0f_link,json=p0fLink" json:"p0f_link,omitempty"`
	P0FTos    []byte    `protobuf:"bytes,69,opt,name=p0f_tos,json=p0fTos" json:"p0f_tos,omitempty"`
	P0FFw     *uint32   `protobuf:"varint,70,opt,name=p0f_fw,json=p0fFw" json:"p0f_fw,omitempty"`
	P0FNat    *uint32   `protobuf:"varint,71,opt,name=p0f_nat,json=p0fNat" json:"p0f_nat,omitempty"`
	P0FReal   *uint32   `protobuf:"varint,72,opt,name=p0f_real,json=p0fReal" json:"p0f_real,omitempty"`
	P0FScore  *int32    `protobuf:"varint,73,opt,name=p0f_score,json=p0fScore" json:"p0f_score,omitempty"`
	P0FMflags *uint32   `protobuf:"varint,74,opt,name=p0f_mflags,json=p0fMflags" json:"p0f_mflags,omitempty"`
	P0FUptime *int32    `protobuf:"varint,75,opt,name=p0f_uptime,json=p0fUptime" json:"p0f_uptime,omitempty"`
}

func (x *Http) Reset() {
	*x = Http{}
	if protoimpl.UnsafeEnabled {
		mi := &file_http_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Http) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Http) ProtoMessage() {}

func (x *Http) ProtoReflect() protoreflect.Message {
	mi := &file_http_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Http.ProtoReflect.Descriptor instead.
func (*Http) Descriptor() ([]byte, []int) {
	return file_http_proto_rawDescGZIP(), []int{0}
}

func (x *Http) GetType() HttpType {
	if x != nil && x.Type != nil {
		return *x.Type
	}
	return HttpType_sinkhole
}

func (x *Http) GetSrcip() []byte {
	if x != nil {
		return x.Srcip
	}
	return nil
}

func (x *Http) GetSrchost() []byte {
	if x != nil {
		return x.Srchost
	}
	return nil
}

func (x *Http) GetSrcport() uint32 {
	if x != nil && x.Srcport != nil {
		return *x.Srcport
	}
	return 0
}

func (x *Http) GetDstip() []byte {
	if x != nil {
		return x.Dstip
	}
	return nil
}

func (x *Http) GetDstport() uint32 {
	if x != nil && x.Dstport != nil {
		return *x.Dstport
	}
	return 0
}

func (x *Http) GetRequest() []byte {
	if x != nil {
		return x.Request
	}
	return nil
}

func (x *Http) GetP0FGenre() []byte {
	if x != nil {
		return x.P0FGenre
	}
	return nil
}

func (x *Http) GetP0FDetail() []byte {
	if x != nil {
		return x.P0FDetail
	}
	return nil
}

func (x *Http) GetP0FDist() int32 {
	if x != nil && x.P0FDist != nil {
		return *x.P0FDist
	}
	return 0
}

func (x *Http) GetP0FLink() []byte {
	if x != nil {
		return x.P0FLink
	}
	return nil
}

func (x *Http) GetP0FTos() []byte {
	if x != nil {
		return x.P0FTos
	}
	return nil
}

func (x *Http) GetP0FFw() uint32 {
	if x != nil && x.P0FFw != nil {
		return *x.P0FFw
	}
	return 0
}

func (x *Http) GetP0FNat() uint32 {
	if x != nil && x.P0FNat != nil {
		return *x.P0FNat
	}
	return 0
}

func (x *Http) GetP0FReal() uint32 {
	if x != nil && x.P0FReal != nil {
		return *x.P0FReal
	}
	return 0
}

func (x *Http) GetP0FScore() int32 {
	if x != nil && x.P0FScore != nil {
		return *x.P0FScore
	}
	return 0
}

func (x *Http) GetP0FMflags() uint32 {
	if x != nil && x.P0FMflags != nil {
		return *x.P0FMflags
	}
	return 0
}

func (x *Http) GetP0FUptime() int32 {
	if x != nil && x.P0FUptime != nil {
		return *x.P0FUptime
	}
	return 0
}

var File_http_proto protoreflect.FileDescriptor

var file_http_proto_rawDesc = []byte{
	0x0a, 0x0a, 0x68, 0x74, 0x74, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x09, 0x6e, 0x6d,
	0x73, 0x67, 0x2e, 0x62, 0x61, 0x73, 0x65, 0x22, 0xf4, 0x03, 0x0a, 0x04, 0x48, 0x74, 0x74, 0x70,
	0x12, 0x27, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20, 0x02, 0x28, 0x0e, 0x32, 0x13,
	0x2e, 0x6e, 0x6d, 0x73, 0x67, 0x2e, 0x62, 0x61, 0x73, 0x65, 0x2e, 0x48, 0x74, 0x74, 0x70, 0x54,
	0x79, 0x70, 0x65, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x73, 0x72, 0x63,
	0x69, 0x70, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x73, 0x72, 0x63, 0x69, 0x70, 0x12,
	0x18, 0x0a, 0x07, 0x73, 0x72, 0x63, 0x68, 0x6f, 0x73, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x07, 0x73, 0x72, 0x63, 0x68, 0x6f, 0x73, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x73, 0x72, 0x63,
	0x70, 0x6f, 0x72, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x73, 0x72, 0x63, 0x70,
	0x6f, 0x72, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x64, 0x73, 0x74, 0x69, 0x70, 0x18, 0x05, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x05, 0x64, 0x73, 0x74, 0x69, 0x70, 0x12, 0x18, 0x0a, 0x07, 0x64, 0x73, 0x74,
	0x70, 0x6f, 0x72, 0x74, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x64, 0x73, 0x74, 0x70,
	0x6f, 0x72, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x18, 0x07,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1b, 0x0a,
	0x09, 0x70, 0x30, 0x66, 0x5f, 0x67, 0x65, 0x6e, 0x72, 0x65, 0x18, 0x41, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x08, 0x70, 0x30, 0x66, 0x47, 0x65, 0x6e, 0x72, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x30,
	0x66, 0x5f, 0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x18, 0x42, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09,
	0x70, 0x30, 0x66, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x12, 0x19, 0x0a, 0x08, 0x70, 0x30, 0x66,
	0x5f, 0x64, 0x69, 0x73, 0x74, 0x18, 0x43, 0x20, 0x01, 0x28, 0x05, 0x52, 0x07, 0x70, 0x30, 0x66,
	0x44, 0x69, 0x73, 0x74, 0x12, 0x19, 0x0a, 0x08, 0x70, 0x30, 0x66, 0x5f, 0x6c, 0x69, 0x6e, 0x6b,
	0x18, 0x44, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x70, 0x30, 0x66, 0x4c, 0x69, 0x6e, 0x6b, 0x12,
	0x17, 0x0a, 0x07, 0x70, 0x30, 0x66, 0x5f, 0x74, 0x6f, 0x73, 0x18, 0x45, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x06, 0x70, 0x30, 0x66, 0x54, 0x6f, 0x73, 0x12, 0x15, 0x0a, 0x06, 0x70, 0x30, 0x66, 0x5f,
	0x66, 0x77, 0x18, 0x46, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x70, 0x30, 0x66, 0x46, 0x77, 0x12,
	0x17, 0x0a, 0x07, 0x70, 0x30, 0x66, 0x5f, 0x6e, 0x61, 0x74, 0x18, 0x47, 0x20, 0x01, 0x28, 0x0d,
	0x52, 0x06, 0x70, 0x30, 0x66, 0x4e, 0x61, 0x74, 0x12, 0x19, 0x0a, 0x08, 0x70, 0x30, 0x66, 0x5f,
	0x72, 0x65, 0x61, 0x6c, 0x18, 0x48, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x70, 0x30, 0x66, 0x52,
	0x65, 0x61, 0x6c, 0x12, 0x1b, 0x0a, 0x09, 0x70, 0x30, 0x66, 0x5f, 0x73, 0x63, 0x6f, 0x72, 0x65,
	0x18, 0x49, 0x20, 0x01, 0x28, 0x05, 0x52, 0x08, 0x70, 0x30, 0x66, 0x53, 0x63, 0x6f, 0x72, 0x65,
	0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x30, 0x66, 0x5f, 0x6d, 0x66, 0x6c, 0x61, 0x67, 0x73, 0x18, 0x4a,
	0x20, 0x01, 0x28, 0x0d, 0x52, 0x09, 0x70, 0x30, 0x66, 0x4d, 0x66, 0x6c, 0x61, 0x67, 0x73, 0x12,
	0x1d, 0x0a, 0x0a, 0x70, 0x30, 0x66, 0x5f, 0x75, 0x70, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x4b, 0x20,
	0x01, 0x28, 0x05, 0x52, 0x09, 0x70, 0x30, 0x66, 0x55, 0x70, 0x74, 0x69, 0x6d, 0x65, 0x2a, 0x18,
	0x0a, 0x08, 0x48, 0x74, 0x74, 0x70, 0x54, 0x79, 0x70, 0x65, 0x12, 0x0c, 0x0a, 0x08, 0x73, 0x69,
	0x6e, 0x6b, 0x68, 0x6f, 0x6c, 0x65, 0x10, 0x01,
}

var (
	file_http_proto_rawDescOnce sync.Once
	file_http_proto_rawDescData = file_http_proto_rawDesc
)

func file_http_proto_rawDescGZIP() []byte {
	file_http_proto_rawDescOnce.Do(func() {
		file_http_proto_rawDescData = protoimpl.X.CompressGZIP(file_http_proto_rawDescData)
	})
	return file_http_proto_rawDescData
}

var file_http_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_http_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_http_proto_goTypes = []interface{}{
	(HttpType)(0), // 0: nmsg.base.HttpType
	(*Http)(nil),  // 1: nmsg.base.Http
}
var file_http_proto_depIdxs = []int32{
	0, // 0: nmsg.base.Http.type:type_name -> nmsg.base.HttpType
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_http_proto_init() }
func file_http_proto_init() {
	if File_http_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_http_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Http); i {
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
			RawDescriptor: file_http_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_http_proto_goTypes,
		DependencyIndexes: file_http_proto_depIdxs,
		EnumInfos:         file_http_proto_enumTypes,
		MessageInfos:      file_http_proto_msgTypes,
	}.Build()
	File_http_proto = out.File
	file_http_proto_rawDesc = nil
	file_http_proto_goTypes = nil
	file_http_proto_depIdxs = nil
}

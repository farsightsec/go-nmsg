// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0-devel
// 	protoc        (unknown)
// source: email.proto

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

type Email_EmailType int32

const (
	Email_unknown     Email_EmailType = 0
	Email_spamtrap    Email_EmailType = 1
	Email_rej_network Email_EmailType = 2
	Email_rej_content Email_EmailType = 3
	Email_rej_user    Email_EmailType = 4
)

// Enum value maps for Email_EmailType.
var (
	Email_EmailType_name = map[int32]string{
		0: "unknown",
		1: "spamtrap",
		2: "rej_network",
		3: "rej_content",
		4: "rej_user",
	}
	Email_EmailType_value = map[string]int32{
		"unknown":     0,
		"spamtrap":    1,
		"rej_network": 2,
		"rej_content": 3,
		"rej_user":    4,
	}
)

func (x Email_EmailType) Enum() *Email_EmailType {
	p := new(Email_EmailType)
	*p = x
	return p
}

func (x Email_EmailType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Email_EmailType) Descriptor() protoreflect.EnumDescriptor {
	return file_email_proto_enumTypes[0].Descriptor()
}

func (Email_EmailType) Type() protoreflect.EnumType {
	return &file_email_proto_enumTypes[0]
}

func (x Email_EmailType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Do not use.
func (x *Email_EmailType) UnmarshalJSON(b []byte) error {
	num, err := protoimpl.X.UnmarshalJSONEnum(x.Descriptor(), b)
	if err != nil {
		return err
	}
	*x = Email_EmailType(num)
	return nil
}

// Deprecated: Use Email_EmailType.Descriptor instead.
func (Email_EmailType) EnumDescriptor() ([]byte, []int) {
	return file_email_proto_rawDescGZIP(), []int{0, 0}
}

type Email struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Type    *Email_EmailType `protobuf:"varint,8,opt,name=type,enum=nmsg.base.Email_EmailType" json:"type,omitempty"`
	Headers []byte           `protobuf:"bytes,2,opt,name=headers" json:"headers,omitempty"`
	Srcip   []byte           `protobuf:"bytes,3,opt,name=srcip" json:"srcip,omitempty"`
	Srchost []byte           `protobuf:"bytes,4,opt,name=srchost" json:"srchost,omitempty"`
	Helo    []byte           `protobuf:"bytes,5,opt,name=helo" json:"helo,omitempty"`
	From    []byte           `protobuf:"bytes,6,opt,name=from" json:"from,omitempty"`
	Rcpt    [][]byte         `protobuf:"bytes,7,rep,name=rcpt" json:"rcpt,omitempty"`
	Bodyurl [][]byte         `protobuf:"bytes,9,rep,name=bodyurl" json:"bodyurl,omitempty"`
	Body    []byte           `protobuf:"bytes,10,opt,name=body" json:"body,omitempty"`
}

func (x *Email) Reset() {
	*x = Email{}
	if protoimpl.UnsafeEnabled {
		mi := &file_email_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Email) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Email) ProtoMessage() {}

func (x *Email) ProtoReflect() protoreflect.Message {
	mi := &file_email_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Email.ProtoReflect.Descriptor instead.
func (*Email) Descriptor() ([]byte, []int) {
	return file_email_proto_rawDescGZIP(), []int{0}
}

func (x *Email) GetType() Email_EmailType {
	if x != nil && x.Type != nil {
		return *x.Type
	}
	return Email_unknown
}

func (x *Email) GetHeaders() []byte {
	if x != nil {
		return x.Headers
	}
	return nil
}

func (x *Email) GetSrcip() []byte {
	if x != nil {
		return x.Srcip
	}
	return nil
}

func (x *Email) GetSrchost() []byte {
	if x != nil {
		return x.Srchost
	}
	return nil
}

func (x *Email) GetHelo() []byte {
	if x != nil {
		return x.Helo
	}
	return nil
}

func (x *Email) GetFrom() []byte {
	if x != nil {
		return x.From
	}
	return nil
}

func (x *Email) GetRcpt() [][]byte {
	if x != nil {
		return x.Rcpt
	}
	return nil
}

func (x *Email) GetBodyurl() [][]byte {
	if x != nil {
		return x.Bodyurl
	}
	return nil
}

func (x *Email) GetBody() []byte {
	if x != nil {
		return x.Body
	}
	return nil
}

var File_email_proto protoreflect.FileDescriptor

var file_email_proto_rawDesc = []byte{
	0x0a, 0x0b, 0x65, 0x6d, 0x61, 0x69, 0x6c, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x09, 0x6e,
	0x6d, 0x73, 0x67, 0x2e, 0x62, 0x61, 0x73, 0x65, 0x22, 0xc3, 0x02, 0x0a, 0x05, 0x45, 0x6d, 0x61,
	0x69, 0x6c, 0x12, 0x2e, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0e,
	0x32, 0x1a, 0x2e, 0x6e, 0x6d, 0x73, 0x67, 0x2e, 0x62, 0x61, 0x73, 0x65, 0x2e, 0x45, 0x6d, 0x61,
	0x69, 0x6c, 0x2e, 0x45, 0x6d, 0x61, 0x69, 0x6c, 0x54, 0x79, 0x70, 0x65, 0x52, 0x04, 0x74, 0x79,
	0x70, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x73, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x07, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x73, 0x12, 0x14, 0x0a, 0x05,
	0x73, 0x72, 0x63, 0x69, 0x70, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x73, 0x72, 0x63,
	0x69, 0x70, 0x12, 0x18, 0x0a, 0x07, 0x73, 0x72, 0x63, 0x68, 0x6f, 0x73, 0x74, 0x18, 0x04, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x07, 0x73, 0x72, 0x63, 0x68, 0x6f, 0x73, 0x74, 0x12, 0x12, 0x0a, 0x04,
	0x68, 0x65, 0x6c, 0x6f, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x68, 0x65, 0x6c, 0x6f,
	0x12, 0x12, 0x0a, 0x04, 0x66, 0x72, 0x6f, 0x6d, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04,
	0x66, 0x72, 0x6f, 0x6d, 0x12, 0x12, 0x0a, 0x04, 0x72, 0x63, 0x70, 0x74, 0x18, 0x07, 0x20, 0x03,
	0x28, 0x0c, 0x52, 0x04, 0x72, 0x63, 0x70, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x62, 0x6f, 0x64, 0x79,
	0x75, 0x72, 0x6c, 0x18, 0x09, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x07, 0x62, 0x6f, 0x64, 0x79, 0x75,
	0x72, 0x6c, 0x12, 0x12, 0x0a, 0x04, 0x62, 0x6f, 0x64, 0x79, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x04, 0x62, 0x6f, 0x64, 0x79, 0x22, 0x56, 0x0a, 0x09, 0x45, 0x6d, 0x61, 0x69, 0x6c, 0x54,
	0x79, 0x70, 0x65, 0x12, 0x0b, 0x0a, 0x07, 0x75, 0x6e, 0x6b, 0x6e, 0x6f, 0x77, 0x6e, 0x10, 0x00,
	0x12, 0x0c, 0x0a, 0x08, 0x73, 0x70, 0x61, 0x6d, 0x74, 0x72, 0x61, 0x70, 0x10, 0x01, 0x12, 0x0f,
	0x0a, 0x0b, 0x72, 0x65, 0x6a, 0x5f, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x10, 0x02, 0x12,
	0x0f, 0x0a, 0x0b, 0x72, 0x65, 0x6a, 0x5f, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x10, 0x03,
	0x12, 0x0c, 0x0a, 0x08, 0x72, 0x65, 0x6a, 0x5f, 0x75, 0x73, 0x65, 0x72, 0x10, 0x04, 0x42, 0x2a,
	0x5a, 0x28, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x66, 0x61, 0x72,
	0x73, 0x69, 0x67, 0x68, 0x74, 0x73, 0x65, 0x63, 0x2f, 0x67, 0x6f, 0x2d, 0x6e, 0x6d, 0x73, 0x67,
	0x2f, 0x6e, 0x6d, 0x73, 0x67, 0x5f, 0x62, 0x61, 0x73, 0x65,
}

var (
	file_email_proto_rawDescOnce sync.Once
	file_email_proto_rawDescData = file_email_proto_rawDesc
)

func file_email_proto_rawDescGZIP() []byte {
	file_email_proto_rawDescOnce.Do(func() {
		file_email_proto_rawDescData = protoimpl.X.CompressGZIP(file_email_proto_rawDescData)
	})
	return file_email_proto_rawDescData
}

var file_email_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_email_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_email_proto_goTypes = []interface{}{
	(Email_EmailType)(0), // 0: nmsg.base.Email.EmailType
	(*Email)(nil),        // 1: nmsg.base.Email
}
var file_email_proto_depIdxs = []int32{
	0, // 0: nmsg.base.Email.type:type_name -> nmsg.base.Email.EmailType
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_email_proto_init() }
func file_email_proto_init() {
	if File_email_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_email_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Email); i {
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
			RawDescriptor: file_email_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_email_proto_goTypes,
		DependencyIndexes: file_email_proto_depIdxs,
		EnumInfos:         file_email_proto_enumTypes,
		MessageInfos:      file_email_proto_msgTypes,
	}.Build()
	File_email_proto = out.File
	file_email_proto_rawDesc = nil
	file_email_proto_goTypes = nil
	file_email_proto_depIdxs = nil
}

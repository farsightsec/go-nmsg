// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.21.12
// source: xml.proto

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

type Xml struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Xmltype    []byte `protobuf:"bytes,1,req,name=xmltype" json:"xmltype,omitempty"`
	Xmlpayload []byte `protobuf:"bytes,2,req,name=xmlpayload" json:"xmlpayload,omitempty"`
}

func (x *Xml) Reset() {
	*x = Xml{}
	if protoimpl.UnsafeEnabled {
		mi := &file_xml_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Xml) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Xml) ProtoMessage() {}

func (x *Xml) ProtoReflect() protoreflect.Message {
	mi := &file_xml_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Xml.ProtoReflect.Descriptor instead.
func (*Xml) Descriptor() ([]byte, []int) {
	return file_xml_proto_rawDescGZIP(), []int{0}
}

func (x *Xml) GetXmltype() []byte {
	if x != nil {
		return x.Xmltype
	}
	return nil
}

func (x *Xml) GetXmlpayload() []byte {
	if x != nil {
		return x.Xmlpayload
	}
	return nil
}

var File_xml_proto protoreflect.FileDescriptor

var file_xml_proto_rawDesc = []byte{
	0x0a, 0x09, 0x78, 0x6d, 0x6c, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x09, 0x6e, 0x6d, 0x73,
	0x67, 0x2e, 0x62, 0x61, 0x73, 0x65, 0x22, 0x3f, 0x0a, 0x03, 0x58, 0x6d, 0x6c, 0x12, 0x18, 0x0a,
	0x07, 0x78, 0x6d, 0x6c, 0x74, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20, 0x02, 0x28, 0x0c, 0x52, 0x07,
	0x78, 0x6d, 0x6c, 0x74, 0x79, 0x70, 0x65, 0x12, 0x1e, 0x0a, 0x0a, 0x78, 0x6d, 0x6c, 0x70, 0x61,
	0x79, 0x6c, 0x6f, 0x61, 0x64, 0x18, 0x02, 0x20, 0x02, 0x28, 0x0c, 0x52, 0x0a, 0x78, 0x6d, 0x6c,
	0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x42, 0x2a, 0x5a, 0x28, 0x67, 0x69, 0x74, 0x68, 0x75,
	0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x66, 0x61, 0x72, 0x73, 0x69, 0x67, 0x68, 0x74, 0x73, 0x65,
	0x63, 0x2f, 0x67, 0x6f, 0x2d, 0x6e, 0x6d, 0x73, 0x67, 0x2f, 0x6e, 0x6d, 0x73, 0x67, 0x5f, 0x62,
	0x61, 0x73, 0x65,
}

var (
	file_xml_proto_rawDescOnce sync.Once
	file_xml_proto_rawDescData = file_xml_proto_rawDesc
)

func file_xml_proto_rawDescGZIP() []byte {
	file_xml_proto_rawDescOnce.Do(func() {
		file_xml_proto_rawDescData = protoimpl.X.CompressGZIP(file_xml_proto_rawDescData)
	})
	return file_xml_proto_rawDescData
}

var file_xml_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_xml_proto_goTypes = []interface{}{
	(*Xml)(nil), // 0: nmsg.base.Xml
}
var file_xml_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_xml_proto_init() }
func file_xml_proto_init() {
	if File_xml_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_xml_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Xml); i {
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
			RawDescriptor: file_xml_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_xml_proto_goTypes,
		DependencyIndexes: file_xml_proto_depIdxs,
		MessageInfos:      file_xml_proto_msgTypes,
	}.Build()
	File_xml_proto = out.File
	file_xml_proto_rawDesc = nil
	file_xml_proto_goTypes = nil
	file_xml_proto_depIdxs = nil
}

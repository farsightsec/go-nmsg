// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0-devel
// 	protoc        (unknown)
// source: logline.proto

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

type LogLine struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Category []byte `protobuf:"bytes,1,opt,name=category" json:"category,omitempty"`
	Message  []byte `protobuf:"bytes,2,opt,name=message" json:"message,omitempty"`
}

func (x *LogLine) Reset() {
	*x = LogLine{}
	if protoimpl.UnsafeEnabled {
		mi := &file_logline_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LogLine) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LogLine) ProtoMessage() {}

func (x *LogLine) ProtoReflect() protoreflect.Message {
	mi := &file_logline_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LogLine.ProtoReflect.Descriptor instead.
func (*LogLine) Descriptor() ([]byte, []int) {
	return file_logline_proto_rawDescGZIP(), []int{0}
}

func (x *LogLine) GetCategory() []byte {
	if x != nil {
		return x.Category
	}
	return nil
}

func (x *LogLine) GetMessage() []byte {
	if x != nil {
		return x.Message
	}
	return nil
}

var File_logline_proto protoreflect.FileDescriptor

var file_logline_proto_rawDesc = []byte{
	0x0a, 0x0d, 0x6c, 0x6f, 0x67, 0x6c, 0x69, 0x6e, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x09, 0x6e, 0x6d, 0x73, 0x67, 0x2e, 0x62, 0x61, 0x73, 0x65, 0x22, 0x3f, 0x0a, 0x07, 0x4c, 0x6f,
	0x67, 0x4c, 0x69, 0x6e, 0x65, 0x12, 0x1a, 0x0a, 0x08, 0x63, 0x61, 0x74, 0x65, 0x67, 0x6f, 0x72,
	0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x08, 0x63, 0x61, 0x74, 0x65, 0x67, 0x6f, 0x72,
	0x79, 0x12, 0x18, 0x0a, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x42, 0x34, 0x5a, 0x32, 0x67,
	0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x66, 0x61, 0x72, 0x73, 0x69, 0x67,
	0x68, 0x74, 0x73, 0x65, 0x63, 0x2f, 0x67, 0x6f, 0x2d, 0x6e, 0x6d, 0x73, 0x67, 0x2f, 0x6e, 0x6d,
	0x73, 0x67, 0x5f, 0x62, 0x61, 0x73, 0x65, 0x3b, 0x6e, 0x6d, 0x73, 0x67, 0x5f, 0x62, 0x61, 0x73,
	0x65,
}

var (
	file_logline_proto_rawDescOnce sync.Once
	file_logline_proto_rawDescData = file_logline_proto_rawDesc
)

func file_logline_proto_rawDescGZIP() []byte {
	file_logline_proto_rawDescOnce.Do(func() {
		file_logline_proto_rawDescData = protoimpl.X.CompressGZIP(file_logline_proto_rawDescData)
	})
	return file_logline_proto_rawDescData
}

var file_logline_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_logline_proto_goTypes = []interface{}{
	(*LogLine)(nil), // 0: nmsg.base.LogLine
}
var file_logline_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_logline_proto_init() }
func file_logline_proto_init() {
	if File_logline_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_logline_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LogLine); i {
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
			RawDescriptor: file_logline_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_logline_proto_goTypes,
		DependencyIndexes: file_logline_proto_depIdxs,
		MessageInfos:      file_logline_proto_msgTypes,
	}.Build()
	File_logline_proto = out.File
	file_logline_proto_rawDesc = nil
	file_logline_proto_goTypes = nil
	file_logline_proto_depIdxs = nil
}

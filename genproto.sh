#!/bin/sh

go_package() {
	local file pkg
	file=$1; shift
	pkg=$1; shift

	grep "^option go_package = \"$pkg\";$" $file > /dev/null && return
	ed $file <<EOF || exit
/^option go_package/d
/^package nmsg/
a
option go_package = "$pkg";
.
w
q
EOF
}

dir=$(dirname $0)
[ -n "$dir" ] && cd $dir

go_package nmsg.proto "github.com/farsightsec/go-nmsg;nmsg"
protoc --go_out=../../.. nmsg.proto

cd nmsg_base
for f in *.proto; do
	go_package $f "github.com/farsightsec/go-nmsg/nmsg_base;nmsg_base"
done

protoc --go_out=../../../.. *.proto

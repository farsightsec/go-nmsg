#!/bin/sh

go_package() {
	local file pkg cleanup
	file=$1; shift
	pkg=$1; shift

	grep "^option go_package = \"$pkg\";$" $file > /dev/null && return
	if grep "^option go_package" $file > /dev/null; then
		cleanup=$(echo "/^option go_package/d:1" | tr : '\n')
	fi
	ed $file <<EOF || exit
$cleanup/^package nmsg/
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
	go_package $f "github.com/farsightsec/go-nmsg/nmsg_base"
done

protoc --go_out=../../../.. *.proto

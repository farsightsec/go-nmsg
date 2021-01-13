#!/bin/sh

go_package() {
	local file pkg line script
	file=$1; shift
	pkg=$1; shift

	line="option go_package = \"$pkg\";"
	grep "^$line\$" $file > /dev/null && return

	script="/^package nmsg/|a|$line|.|w|q|"
	if grep "^option go_package" $file > /dev/null; then
		script="/^option go_package/d|1|${script}"
	fi
	echo "$script" | tr '|' '\n' | ed $file || exit
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

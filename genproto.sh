#!/bin/sh

dir=$(dirname $0)
[ -n "$dir" ] && cd $dir

protoc --go_out=../../.. nmsg.proto
cd nmsg_base
protoc --go_out=../../../.. *.proto

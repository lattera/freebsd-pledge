#!/bin/sh
if [ $# -lt 1 ]
then
	echo 1>&2 "usage: $0 sandbox-dir [curtain-opts] [cmd] [cmd-opts ...]"
	exit 64
fi
d="$1"
shift
case "$d" in
(/*) ;;
(*) d="$(pwd)/$d" || exit ;;
esac
export SANDBOX_HOME="$d"
exec curtain \
	-p "$d":rwus \
	-t _home_sandbox \
	--setenv HOME="$d" \
	-S "$@"

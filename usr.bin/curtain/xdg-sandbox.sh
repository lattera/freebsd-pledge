#!/bin/sh
if [ $# -lt 1 ]
then
	echo 1>&2 "usage: $0 base-dir [curtain-opts] [cmd] [cmd-opts ...]"
	exit 64
fi
d="$1"
shift
case "$d" in
(/*) ;;
(*) d="$(pwd)/$d" || exit ;;
esac
export SANDBOX_XDG="$d"
export XDG_DATA_HOME="$d/data"
export XDG_STATE_HOME="$d/state"
export XDG_CONFIG_HOME="$d/config"
export XDG_CACHE_HOME="$d/cache"
mkdir -p "$XDG_DATA_HOME" || exit
mkdir -p "$XDG_STATE_HOME" || exit
mkdir -p "$XDG_CONFIG_HOME" || exit
mkdir -p "$XDG_CACHE_HOME" || exit
exec curtain \
	-p "$d":rwu \
	-t _xdg_sandbox \
	-s "$@"

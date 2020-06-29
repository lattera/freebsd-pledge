#!/bin/sh
exec execpledge \
	-p error,capsicum,stdio,rpath,wpath,cpath,dpath,tmppath,flock,fattr,chown,id,proc,thread,exec,tty,dns,inet,unix \
	-u /lib \
	-u /usr/lib \
	-u /usr/local/lib \
	-u /libexec \
	-u /usr/libexec \
	-u /bin \
	-u /sbin \
	-u /usr/bin \
	-u /usr/sbin \
	-u /usr/local/bin \
	-u /usr/local/sbin \
	-u /usr/share \
	-u /usr/local/share \
	"$@"

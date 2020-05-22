#!/bin/sh
exec execpledge \
	-p error,capsicum,stdio,rpath,wpath,cpath,dpath,tmppath,flock,fattr,chown,id,proc,thread,exec,tty,inet,unix \
	-u /lib \
	-u /usr/lib \
	-u /usr/local/lib \
	-u /usr/share \
	-u /usr/local/share \
	-u /var/tmp:rwc \
	-u /libexec:x \
	-u /bin \
	-u /sbin \
	-u /usr/bin \
	-u /usr/sbin \
	-u /usr/local/bin \
	-u /usr/local/sbin \
	-u /:i \
	"$@"

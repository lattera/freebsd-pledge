BEGIN {
	print "#include <stddef.h>"
	print "#include <sys/socket.h>"
	print "#include <netinet/in.h>"
	print "#include \"common.h\""
	print
	print "const struct socklvlent socklvltab[] = {"
	print "\t{ \"socket\", SOL_SOCKET },"
}
/^[[:space:]]*#[[:space:]]*define[[:space:]]+IPPROTO_/ {
	if ($2 == "IPPROTO_SPACER")
		nextfile
	print "#ifdef " $2
	print "\t{ " "\"" tolower(substr($2, 9)) "\"" ", " $2 " },"
	print "#endif"
}
END {
	print "\t{ NULL, -1 }"
	print "};"
}

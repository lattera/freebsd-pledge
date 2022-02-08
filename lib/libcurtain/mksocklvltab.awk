BEGIN {
	print "#include <stddef.h>"
	print "#include <sys/socket.h>"
	print "#include <netinet/in.h>"
	print "#include <sys/un.h>"
	print "#include \"common.h\""
	print
	print "const struct socklvlent curtain_socklvltab[] = {"
	print "\t{ \"socket\", SOL_SOCKET },"
	print "\t{ \"local\", SOL_LOCAL },"
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

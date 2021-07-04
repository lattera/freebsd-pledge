BEGIN {
	print "#include <stddef.h>"
	print "#include <sys/socket.h>"
	print "#include \"common.h\""
	print
	print "const struct sockafent curtain_sockaftab[] = {"
}

/^[[:space:]]*#[[:space:]]*define[[:space:]]+AF_/ {
	if ($2 == "AF_UNSPEC") {
		start = 1
		next
	}
	if ($2 == "AF_MAX")
		nextfile
	if (!start)
		next
	print "#ifdef " $2
	print "\t{ " "\"" tolower(substr($2, 4)) "\"" ", " $2 " },"
	print "#endif"
}
END {
	print "\t{ NULL, -1 }"
	print "};"
}

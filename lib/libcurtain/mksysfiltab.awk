BEGIN {
	print "#include <stddef.h>"
	print "#include <sys/sysfil.h>"
	print "#include \"common.h\""
	print
	print "const struct sysfilent curtain_sysfiltab[] = {"
}
/^[[:space:]]*#[[:space:]]*define[[:space:]]+SYSFIL_/ {
	if ($2 == "SYSFIL_LAST")
		nextfile
	if (substr($2, 8, 1) == "_")
		next
	print "#ifdef " $2
	print "\t{ " "\"" tolower(substr($2, 8)) "\"" ", " $2 " },"
	print "#endif"
}
END {
	print "\t{ NULL, -1 }"
	print "};"
}

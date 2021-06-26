BEGIN {
	print "#include <stddef.h>"
	print "#include <sys/sysfil.h>"
	print "#include \"common.h\""
	print
	print "const struct sysfilent sysfiltab[] = {"
}
/^[[:space:]]*#[[:space:]]*define[[:space:]]+SYSFIL_/ {
	if ($2 == "SYSFIL_LAST")
		nextfile;
	print "\t{ " "\"" tolower(substr($2, 8)) "\"" ", " $2 " },";
}
END {
	print "\t{ NULL, -1 }"
	print "};"
}

BEGIN {
	print "#include <stddef.h>"
	print "#include <sys/priv.h>"
	print "#include \"common.h\""
	print
	print "const struct privent privtab[] = {"
}
/^[[:space:]]*#[[:space:]]*define[[:space:]]+_?PRIV_/ {
	if ($2 == "_PRIV_HIGHEST")
		nextfile;
	if (substr($2, 1, 1) == "_")
		next;
	print "\t{ " "\"" tolower(substr($2, 6)) "\"" ", " $2 " },";
}
END {
	print "\t{ NULL, -1 }"
	print "};"
}

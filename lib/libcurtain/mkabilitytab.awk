BEGIN {
	print "#include <stddef.h>"
	print "#include <sys/curtain_ability.h>"
	print "#include \"common.h\""
	print
	print "const struct abilityent curtain_abilitytab[] = {"
}
/^[[:space:]]*CURTAINABL_[A-Z_]+([[:space:]]*=[[:space:]]*(0x?)?[0-9]+)?[[:space:]]*,/ {
	print "\t{ " "\"" tolower(substr($1, 12)) "\"" ", " $1 " },"
}
END {
	print "\t{ NULL, -1 }"
	print "};"
}

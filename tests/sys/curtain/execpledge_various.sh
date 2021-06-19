
atf_test_case cmd_true
cmd_true_body() {
	atf_check -s exit:0 -e empty -o empty execpledge -p 'stdio rpath' true
}

atf_test_case cmd_false
cmd_false_body() {
	atf_check -s exit:1 -e empty -o empty execpledge -p 'stdio rpath' false
}

atf_test_case cmd_echo
cmd_echo_body() {
	atf_check -s exit:0 -e empty -o inline:'test' execpledge -p 'stdio rpath' echo -n test
}

atf_test_case cmd_cat
cmd_cat_body() {
	local f="/etc/rc"
	atf_check -s exit:0 -e empty -o file:"$f" execpledge -p 'stdio rpath' cat "$f"
}

atf_test_case cmd_execpledge_cat
cmd_execpledge_cat_body() {
	local f="/etc/rc"
	atf_check -s exit:0 -e empty -o file:"$f" execpledge -p 'stdio rpath exec' execpledge -p 'stdio rpath' cat "$f"
}

atf_test_case cmd_mktemp
cmd_mktemp_body() {
	local p="stdio rpath tmppath"
	atf_check -o save:"stdout" execpledge -p "$p" mktemp -t "test"
	local f="$(cat stdout)"
	atf_check test -f "$f"
	atf_check execpledge -p "$p" sh -c 'echo >"$1" "test-content"' . "$f"
	atf_check -o inline:"test-content\n" execpledge -p "$p" cat "$f"
	atf_check unlink "$f"
}


atf_init_test_cases() {
	atf_add_test_case cmd_true
	atf_add_test_case cmd_false
	atf_add_test_case cmd_echo
	atf_add_test_case cmd_cat
	atf_add_test_case cmd_execpledge_cat
	atf_add_test_case cmd_mktemp
}

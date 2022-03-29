
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

atf_test_case test_hard_link_source_perms
test_hard_link_source_perms_body() {
	mkdir 1 2 3 || atf_fail 'mkdir'
	touch 1/a 2/b || atf_fail 'touch'
	pledge='error,stdio,rpath,wpath,cpath,fattr'
	atf_check -s not-exit:0 -e not-empty execpledge -p "$pledge" -u /:rx -u 1:r -u 2:rwc ln 1/a 2/
	atf_check -s not-exit:0 -e not-empty execpledge -p "$pledge" -u /:rx -u 1:r -u 2:rwc ln 1/a 2/a
	atf_check -s exit:0 -e empty execpledge -p "$pledge" -u /:rx -u 2:rwc -u 3:rwc ln 2/b 3/
	atf_check -s exit:0 -e empty execpledge -p "$pledge" -u /:rx -u 2:rwc -u 3:rwc ln 2/b 3/a
}


atf_init_test_cases() {
	atf_add_test_case cmd_true
	atf_add_test_case cmd_false
	atf_add_test_case cmd_echo
	atf_add_test_case cmd_cat
	atf_add_test_case cmd_execpledge_cat
	atf_add_test_case cmd_mktemp
	atf_add_test_case test_hard_link_source_perms
}

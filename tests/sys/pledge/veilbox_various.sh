
atf_test_case cmd_true
cmd_true_body() {
	atf_check -s exit:0 -e empty -o empty veilbox true
}

atf_test_case cmd_false
cmd_false_body() {
	atf_check -s exit:1 -e empty -o empty veilbox false
}

atf_test_case cmd_echo
cmd_echo_body() {
	atf_check -s exit:0 -e empty -o inline:'test' veilbox echo -n test
}

atf_test_case cmd_cat
cmd_cat_body() {
	local f="/etc/rc"
	atf_check -s not-exit:0 -e not-empty -o empty veilbox cat "$f"
	atf_check -s exit:0 -e empty -o file:"$f" veilbox -u "$f" cat "$f"
}

atf_test_case cmd_veilbox_cat
cmd_veilbox_cat_body() {
	local f="/etc/rc"
	atf_check -s not-exit:0 -e not-empty -o empty veilbox veilbox -u "$f" cat "$f"
	atf_check -s not-exit:0 -e not-empty -o empty veilbox -u "$f" veilbox cat "$f"
	atf_check -s not-exit:0 -e not-empty -o empty veilbox veilbox cat "$f"
	atf_check -s exit:0 -e empty -o file:"$f" veilbox -u "$f" veilbox -u "$f" cat "$f"
}


atf_test_case cmd_execpledge_true
cmd_execpledge_true_body() {
	atf_check -s exit:0 -e empty -o empty veilbox execpledge -p 'stdio rpath' true
}

atf_test_case cmd_execpledge_false
cmd_execpledge_false_body() {
	atf_check -s exit:1 -e empty -o empty veilbox execpledge -p 'stdio rpath' false
}

atf_test_case cmd_execpledge_echo
cmd_execpledge_echo_body() {
	atf_check -s exit:0 -e empty -o inline:'test' veilbox execpledge -p 'stdio rpath' echo -n test
}

atf_test_case cmd_execpledge_cat
cmd_execpledge_cat_body() {
	local f="/etc/rc"
	atf_check -s not-exit:0 -e not-empty -o empty veilbox execpledge -p 'stdio rpath' cat "$f"
	atf_check -s exit:0 -e empty -o file:"$f" veilbox -u "$f" execpledge -p 'stdio rpath' cat "$f"
}

atf_test_case cmd_veilbox_execpledge_cat
cmd_veilbox_execpledge_cat_body() {
	local f="/etc/rc"
	atf_check -s not-exit:0 -e not-empty -o empty veilbox veilbox -u "$f" execpledge -p 'stdio rpath' cat "$f"
	atf_check -s not-exit:0 -e not-empty -o empty veilbox -u "$f" veilbox execpledge -p 'stdio rpath' cat "$f"
	atf_check -s not-exit:0 -e not-empty -o empty veilbox veilbox execpledge -p 'stdio rpath' cat "$f"
	atf_check -s exit:0 -e empty -o file:"$f" veilbox -u "$f" veilbox -u "$f" execpledge -p 'stdio rpath' cat "$f"
}


atf_init_test_cases() {
	atf_add_test_case cmd_true
	atf_add_test_case cmd_false
	atf_add_test_case cmd_echo
	atf_add_test_case cmd_cat
	atf_add_test_case cmd_veilbox_cat
	atf_add_test_case cmd_execpledge_true
	atf_add_test_case cmd_execpledge_false
	atf_add_test_case cmd_execpledge_echo
	atf_add_test_case cmd_execpledge_cat
	atf_add_test_case cmd_veilbox_execpledge_cat
}

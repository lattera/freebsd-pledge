
atf_test_case cmd_true
cmd_true_body() {
	atf_check -s exit:0 -e empty -o empty curtain true
}

atf_test_case cmd_false
cmd_false_body() {
	atf_check -s exit:1 -e empty -o empty curtain false
}

atf_test_case cmd_echo
cmd_echo_body() {
	atf_check -s exit:0 -e empty -o inline:'test' curtain echo -n test
}

atf_test_case cmd_cat
cmd_cat_body() {
	local f="/etc/rc"
	atf_check -s not-exit:0 -e not-empty -o empty curtain cat "$f"
	atf_check -s exit:0 -e empty -o file:"$f" curtain -u "$f" cat "$f"
}

atf_test_case cmd_curtain_cat
cmd_curtain_cat_body() {
	local f="/etc/rc"
	atf_check -s not-exit:0 -e not-empty -o empty curtain curtain -u "$f" cat "$f"
	atf_check -s not-exit:0 -e not-empty -o empty curtain -u "$f" curtain cat "$f"
	atf_check -s not-exit:0 -e not-empty -o empty curtain curtain cat "$f"
	atf_check -s exit:0 -e empty -o file:"$f" curtain -u "$f" curtain -u "$f" cat "$f"
}


atf_test_case cmd_execpledge_true
cmd_execpledge_true_body() {
	atf_check -s exit:0 -e empty -o empty curtain execpledge -p 'stdio rpath' true
}

atf_test_case cmd_execpledge_false
cmd_execpledge_false_body() {
	atf_check -s exit:1 -e empty -o empty curtain execpledge -p 'stdio rpath' false
}

atf_test_case cmd_execpledge_echo
cmd_execpledge_echo_body() {
	atf_check -s exit:0 -e empty -o inline:'test' curtain execpledge -p 'stdio rpath' echo -n test
}

atf_test_case cmd_execpledge_cat
cmd_execpledge_cat_body() {
	local f="/etc/rc"
	atf_check -s not-exit:0 -e not-empty -o empty curtain execpledge -p 'stdio rpath' cat "$f"
	atf_check -s exit:0 -e empty -o file:"$f" curtain -u "$f" execpledge -p 'stdio rpath' cat "$f"
}

atf_test_case cmd_curtain_execpledge_cat
cmd_curtain_execpledge_cat_body() {
	local f="/etc/rc"
	atf_check -s not-exit:0 -e not-empty -o empty curtain curtain -u "$f" execpledge -p 'stdio rpath' cat "$f"
	atf_check -s not-exit:0 -e not-empty -o empty curtain -u "$f" curtain execpledge -p 'stdio rpath' cat "$f"
	atf_check -s not-exit:0 -e not-empty -o empty curtain curtain execpledge -p 'stdio rpath' cat "$f"
	atf_check -s exit:0 -e empty -o file:"$f" curtain -u "$f" curtain -u "$f" execpledge -p 'stdio rpath' cat "$f"
}

atf_test_case date_localtime # check if localtime(3) works
date_localtime_body() {
	local t="$(date +%s)"
	date -r "$t" > expected
	atf_check -s exit:0 -e empty -o file:expected curtain date -r "$t"
}

atf_test_case sh_bg_wait # check if basic job control is allowed
sh_bg_wait_body() {
	echo 'true & true & true & wait' | curtain -s
}

atf_test_case ps_visibility
ps_visibility_body() {
	atf_check -s exit:0 -o not-empty curtain sh -c 'exec ps -p $$'
	atf_check -s exit:0 -o not-empty curtain sh -c 'ps -p $$'
	atf_check -s not-exit:0 -o empty -e not-empty curtain ps -p $$
}

atf_init_test_cases() {
	atf_add_test_case cmd_true
	atf_add_test_case cmd_false
	atf_add_test_case cmd_echo
	atf_add_test_case cmd_cat
	atf_add_test_case cmd_curtain_cat
	atf_add_test_case cmd_execpledge_true
	atf_add_test_case cmd_execpledge_false
	atf_add_test_case cmd_execpledge_echo
	atf_add_test_case cmd_execpledge_cat
	atf_add_test_case cmd_curtain_execpledge_cat
	atf_add_test_case date_localtime
	atf_add_test_case sh_bg_wait
	atf_add_test_case ps_visibility
}

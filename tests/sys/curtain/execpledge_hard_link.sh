
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
	atf_add_test_case test_hard_link_source_perms
}

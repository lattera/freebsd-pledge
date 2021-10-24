
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
	atf_check -s not-exit:0 -e not-empty -o empty curtain -t curtain curtain -u "$f" cat "$f"
	atf_check -s not-exit:0 -e not-empty -o empty curtain -t curtain -u "$f" curtain cat "$f"
	atf_check -s not-exit:0 -e not-empty -o empty curtain -t curtain curtain cat "$f"
	atf_check -s exit:0 -e empty -o file:"$f" curtain -t curtain -u "$f" curtain -u "$f" cat "$f"
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
	atf_check -s not-exit:0 -e not-empty -o empty curtain -t curtain curtain -u "$f" execpledge -p 'stdio rpath' cat "$f"
	atf_check -s not-exit:0 -e not-empty -o empty curtain -t curtain -u "$f" curtain execpledge -p 'stdio rpath' cat "$f"
	atf_check -s not-exit:0 -e not-empty -o empty curtain -t curtain curtain execpledge -p 'stdio rpath' cat "$f"
	atf_check -s exit:0 -e empty -o file:"$f" curtain -t curtain -u "$f" curtain -u "$f" execpledge -p 'stdio rpath' cat "$f"
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

atf_test_case kill_restriction
kill_restriction_body() {
	atf_check -s signal:sigterm curtain -f sh -c 'kill $$'
	atf_check -s exit:0 curtain sh -c 'sleep 100 & kill $!'
	atf_check -s not-exit:0 -e not-empty curtain kill $$
	sleep 100 & atf_check -s not-exit:0 -e not-empty curtain kill $! && kill $!
}

atf_test_case ps_visibility
ps_visibility_body() {
	atf_check -s exit:0 -o not-empty curtain sh -c 'ps -o pid= -p $$'
	atf_check -s exit:0 -o not-empty curtain sh -c 'sleep 100 & ps -o pid= -p $! && kill $!'
	atf_check -s not-exit:0 -o empty curtain ps -o pid= -p $$
	sleep 100 & atf_check -s not-exit:0 -o empty curtain ps -o pid= -p $$ && kill $!
}

atf_test_case session_with_non_tty
session_with_non_tty_body() {
	ps -o sid -p $$ > not-exp
	echo 'ps -o sid -p $$' | atf_check -o not-file:not-exp curtain -o newsid -s
}

atf_test_case script_with_cmd # this tests openpty(3)
script_with_cmd_body() {
	atf_check -o not-empty curtain -t _pty -u typescript:w script typescript echo test
	sed -e '1d' -e '$d' -e 's;\r$;!;g' typescript > out
	cat << '.' >> exp
Command: echo test
test!

Command exit status: 0
.
	atf_check -o file:exp cat out
}

atf_test_case script_tty_visibility
script_tty_visibility_body() {
	atf_check -o not-empty \
		curtain -t _pty \
		script /dev/null sh -c 'stat "$(tty)"'
	atf_check -o not-empty \
		curtain -t _pty \
		script /dev/null sh -c 'script /dev/null stat "$(tty)"'
	atf_check -s not-exit:0 -o not-empty \
		curtain -t _pty -t curtain \
		script /dev/null sh -c 'curtain -t _pty stat "$(tty)"'
	atf_check -s not-exit:0 -o not-empty \
		curtain -t _pty -t curtain \
		script /dev/null sh -c 'curtain -t _pty script /dev/null stat "$(tty)"'
}

atf_test_case tmpdir_mkdir_p
tmpdir_mkdir_p_body() {
	atf_check curtain sh -c 'mkdir -p "$TMPDIR/test" && rmdir "$TMPDIR/test"'
}

atf_test_case shared_tmpdir_protects_krb5cc
shared_tmpdir_protects_krb5cc_body() {
	local newtmpdir="$(mktemp -d -t test)" || exit
	local krb5cc="$newtmpdir/krb5cc_$(id -u)"
	local readable="$newtmpdir/readable"
	echo test1 > "$readable"
	TMPDIR="$newtmpdir" atf_check -o file:"$readable" \
		curtain -f cat "$readable"
	atf_check unlink "$readable"
	echo test2 > "$krb5cc"
	TMPDIR="$newtmpdir" atf_check -s not-exit:0 -o empty -e not-empty \
		curtain -f cat "$krb5cc"
	atf_check unlink "$krb5cc"
	atf_check rmdir "$newtmpdir"
}

atf_test_case posixshm_restriction
posixshm_restriction_body() {
	atf_check curtain -d ability:posixipc \
		sh -c 'posixshmcontrol create /test && posixshmcontrol dump /test && posixshmcontrol rm /test'
	local p="/tests/curtain-posix-shm-test"
	atf_check posixshmcontrol create "$p/test"
	atf_check posixshmcontrol dump "$p/test"
	atf_check -s not-exit:0 -e not-empty curtain -d ability:posixipc \
		posixshmcontrol dump "$p/test"
	atf_check posixshmcontrol rm "$p/test"
}

atf_test_case cmd_timeout
cmd_timeout_body() {
	atf_check -s exit:124 curtain -d ability:reap timeout 0.05 sleep 10
	atf_check -s exit:124 curtain -d ability:reap -t curtain timeout 0.05 curtain -f sleep 10
}

atf_test_case cmd_id
cmd_id_body() {
	atf_check -o save:exp id
	atf_check -o file:exp curtain -t _pwddb id
}

atf_test_case uncurtain
uncurtain_body() {
	[ "$(sysctl -n security.curtain.curtained)" = 0 ] || atf_skip "already curtained"
	atf_check -o inline:"0\n" sysctl -n security.curtain.curtained
	atf_check -o inline:"0\n" sysctl -n security.curtain.curtained_exec
	atf_check -o inline:"1\n" curtain sysctl -n security.curtain.curtained
	atf_check -o inline:"1\n" curtain sysctl -n security.curtain.curtained_exec
	atf_check -o inline:"1\n" curtain -t curtain curtain -d default-pass sysctl -n security.curtain.curtained
	atf_check -o inline:"1\n" curtain -t curtain curtain -d default-pass sysctl -n security.curtain.curtained_exec
	atf_check -o inline:"0\n" curtain -t curtain -U curtain -d default-pass sysctl -n security.curtain.curtained
	atf_check -o inline:"0\n" curtain -t curtain -U curtain -d default-pass sysctl -n security.curtain.curtained_exec
}

atf_test_case unenforced_unveil
unenforced_unveil_body() {
	atf_check -o save:f echo test
	atf_check -o file:f curtain -U -t curtain curtain -u f cat f
	atf_check -o file:f curtain -U -t curtain curtain -u / cat f
	atf_check -o file:f curtain -U -t curtain curtain -U -t curtain curtain -u f cat f
	atf_check -o file:f curtain -U -t curtain curtain -U -t curtain curtain -u / cat f
	atf_check -s not-exit:0 -o empty -e not-empty curtain -U -t curtain curtain -t curtain curtain -u f cat f
	atf_check -s not-exit:0 -o empty -e not-empty curtain -U -t curtain curtain -t curtain curtain -u / cat f
}

atf_test_case extattrs
extattrs_body() {
	atf_check touch f
	lsextattr user f || atf_skip "extended attributes not supported?"
	atf_check -o save:exp-ls-0 lsextattr user f
	atf_check setextattr user k V f
	atf_check -o save:exp-get-0 getextattr user k f
	atf_check setextattr user k v f
	atf_check -o save:exp-ls-1 lsextattr user f
	atf_check -o save:exp-get-1 getextattr user k f
	atf_check -s not-exit:0 -e not-empty curtain lsextattr user f
	atf_check -s not-exit:0 -e not-empty curtain getextattr user k f
	atf_check -s not-exit:0 -e not-empty curtain setextattr user k V f
	atf_check -s not-exit:0 -e not-empty curtain rmextattr user k f
	atf_check -o file:exp-ls-1 curtain -d ability:extattr -u f lsextattr user f
	atf_check -o file:exp-get-1 curtain -d ability:extattr -u f getextattr user k f
	atf_check -s not-exit:0 -e not-empty curtain -d ability:extattr -u f:r setextattr user k V f
	atf_check curtain -d ability:extattr -u f:rw setextattr user k V f
	atf_check -o file:exp-get-0 curtain -d ability:extattr -u f getextattr user k f
	atf_check -s not-exit:0 -e not-empty curtain -d ability:extattr -u f:r rmextattr user k f
	atf_check curtain -d ability:extattr -u f:rw rmextattr user k f
	atf_check -o file:exp-ls-0 curtain -d ability:extattr -u f lsextattr user f
}

atf_test_case reunveil_inheritance
reunveil_inheritance_body() {
	atf_check mkdir -p a/b/c/d
	atf_check touch a/b/c/d/f
	curtain -t curtain -u a:rw -u a/b/c:r -u a/b/c/d: -u a/b/c/d/f:rw \
		curtain -u /:rw test \
			\( -r a -a -w a \) -a \
			\( -r a/b -a -w a/b \) -a \
			\( -r a/b/c -a ! -w a/b/c \) -a \
			\( ! -r a/b/c/d -a ! -w a/b/c/d \) -a \
			\( -r a/b/c/d/f -a -w a/b/c/d/f \)
}

atf_test_case chflags
chflags_body() {
	atf_check touch f
	chflags uchg f || atf_skip "chflags not supported?"
	atf_check -s not-exit:0 -e not-empty curtain -2 -u f:rw chflags 0 f
	atf_check -s not-exit:0 -e not-empty curtain -2 -d ability:chflags -u f:r chflags 0 f
	atf_check curtain -2 -d ability:chflags -u f:rw chflags 0 f
}

atf_test_case chflags_system
chflags_system_body() {
	atf_check touch f
	chflags schg f || atf_skip "modifying system flags already disabled"
	atf_check -s not-exit:0 -e not-empty curtain -2 -u f:rw chflags 0 f
	atf_check -s not-exit:0 -e not-empty curtain -2 -d ability:chflags -d ability:sysflags -u f:r chflags 0 f
	atf_check curtain -2 -d ability:chflags -d ability:sysflags -u f:rw chflags 0 f
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
	atf_add_test_case kill_restriction
	atf_add_test_case ps_visibility
	atf_add_test_case script_with_cmd
	atf_add_test_case script_tty_visibility
	atf_add_test_case session_with_non_tty
	atf_add_test_case tmpdir_mkdir_p
	atf_add_test_case shared_tmpdir_protects_krb5cc
	atf_add_test_case posixshm_restriction
	atf_add_test_case cmd_timeout
	atf_add_test_case cmd_id
	atf_add_test_case uncurtain
	atf_add_test_case unenforced_unveil
	atf_add_test_case extattrs
	atf_add_test_case reunveil_inheritance
	atf_add_test_case chflags
	atf_add_test_case chflags_system
}

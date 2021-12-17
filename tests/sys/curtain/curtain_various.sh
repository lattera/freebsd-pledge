
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
	atf_check -s exit:0 -e empty -o file:"$f" curtain -p "$f" cat "$f"
}

atf_test_case cmd_curtain_cat
cmd_curtain_cat_body() {
	local f="/etc/rc"
	atf_check -s not-exit:0 -e not-empty -o empty curtain -t curtain curtain -p "$f" cat "$f"
	atf_check -s not-exit:0 -e not-empty -o empty curtain -t curtain -p "$f" curtain cat "$f"
	atf_check -s not-exit:0 -e not-empty -o empty curtain -t curtain curtain cat "$f"
	atf_check -s exit:0 -e empty -o file:"$f" curtain -t curtain -p "$f" curtain -p "$f" cat "$f"
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
	atf_check -s exit:0 -e empty -o file:"$f" curtain -p "$f" execpledge -p 'stdio rpath' cat "$f"
}

atf_test_case cmd_curtain_execpledge_cat
cmd_curtain_execpledge_cat_body() {
	local f="/etc/rc"
	atf_check -s not-exit:0 -e not-empty -o empty curtain -t curtain curtain -p "$f" execpledge -p 'stdio rpath' cat "$f"
	atf_check -s not-exit:0 -e not-empty -o empty curtain -t curtain -p "$f" curtain execpledge -p 'stdio rpath' cat "$f"
	atf_check -s not-exit:0 -e not-empty -o empty curtain -t curtain curtain execpledge -p 'stdio rpath' cat "$f"
	atf_check -s exit:0 -e empty -o file:"$f" curtain -t curtain -p "$f" curtain -p "$f" execpledge -p 'stdio rpath' cat "$f"
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
	atf_check -o not-empty curtain -t _pty -p typescript:w script typescript echo test
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
	atf_check -o save:exp id -u
	atf_check -o file:exp curtain id -u
	atf_check -o save:exp id -g
	atf_check -o file:exp curtain id -g
	atf_check -o save:exp id
	atf_check -o file:exp curtain -t _pwddb id
	atf_check -o save:exp id -p
	atf_check -o file:exp curtain -t _pwddb id -p
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
	atf_check -o file:f curtain -U -t curtain curtain -p f cat f
	atf_check -o file:f curtain -U -t curtain curtain -p / cat f
	atf_check -o file:f curtain -U -t curtain curtain -U -t curtain curtain -p f cat f
	atf_check -o file:f curtain -U -t curtain curtain -U -t curtain curtain -p / cat f
	atf_check -s not-exit:0 -o empty -e not-empty curtain -U -t curtain curtain -t curtain curtain -p f cat f
	atf_check -s not-exit:0 -o empty -e not-empty curtain -U -t curtain curtain -t curtain curtain -p / cat f
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
	atf_check -o file:exp-ls-1 curtain -d ability:extattr -p f lsextattr user f
	atf_check -o file:exp-get-1 curtain -d ability:extattr -p f getextattr user k f
	atf_check -s not-exit:0 -e not-empty curtain -d ability:extattr -p f:r setextattr user k V f
	atf_check curtain -d ability:extattr -p f:rw setextattr user k V f
	atf_check -o file:exp-get-0 curtain -d ability:extattr -p f getextattr user k f
	atf_check -s not-exit:0 -e not-empty curtain -d ability:extattr -p f:r rmextattr user k f
	atf_check curtain -d ability:extattr -p f:rw rmextattr user k f
	atf_check -o file:exp-ls-0 curtain -d ability:extattr -p f lsextattr user f
}

atf_test_case unveil_dotdot
unveil_dotdot_body() {
	mkdir -p a/b/c
	local p
	for p in a/b/c a/b/c/../c a/b/c/../../b/c a/b/../b/c a/../a/b/c a/../a/b/c/../c a/b/c/../../b/c
	do atf_check curtain -u $p test ! -r a -a ! -r a/b -a -r a/b/c
	done
	for p in a/b a/b/c/.. a/b/../b a/b/c/../../b a/b/../b/../b/c/../../b
	do atf_check curtain -u $p test ! -r a -a -r a/b -a -r a/b/c
	done
	for p in a a/b/.. a/b/c/../.. a/b/../b/../b/c/../c/../../b/..
	do atf_check curtain -u $p test -r a -a -r a/b -a -r a/b/c
	done
}

atf_test_case reunveil_inheritance
reunveil_inheritance_body() {
	atf_check mkdir -p a/b/c/d
	atf_check touch a/b/c/d/f
	atf_check chmod +x a/b/c/d/f
	atf_check curtain -t curtain -u a:rw -u a/b/c:r -u a/b/c/d: -u a/b/c/d/f:rwx \
		curtain -u /:rw test \
			\( -r a -a -w a \) -a \
			\( -r a/b -a -w a/b \) -a \
			\( -r a/b/c -a ! -w a/b/c \) -a \
			\( ! -r a/b/c/d -a ! -w a/b/c/d \) -a \
			\( -r a/b/c/d/f -a -w a/b/c/d/f -a ! -x a/b/c/d/f \)
}

atf_test_case chflags
chflags_body() {
	atf_check touch f
	chflags uchg f || atf_skip "chflags not supported?"
	atf_check -s not-exit:0 -e not-empty curtain -2 -p f:rw chflags 0 f
	atf_check -s not-exit:0 -e not-empty curtain -2 -d ability:chflags -p f:r chflags 0 f
	atf_check curtain -2 -d ability:chflags -p f:rw chflags 0 f
}

atf_test_case chflags_system
chflags_system_body() {
	atf_check touch f
	chflags schg f || atf_skip "modifying system flags already disabled"
	atf_check -s not-exit:0 -e not-empty curtain -2 -p f:rw chflags 0 f
	atf_check -s not-exit:0 -e not-empty curtain -2 -d ability:chflags -d ability:sysflags -p f:r chflags 0 f
	atf_check curtain -2 -d ability:chflags -d ability:sysflags -p f:rw chflags 0 f
}

atf_test_case filtered_ls
filtered_ls_body() {
	atf_check mkdir d
	atf_check touch d/1 d/2 d/3
	atf_check -o empty curtain -p d:li ls d
	atf_check -o inline:'1\n2\n3\n' curtain -p d ls d
	atf_check -o inline:'1\n2\n3\n' curtain -p d/1 -p d/2 -p d/3 ls d
	atf_check -o inline:'1\n' curtain -p d/1 ls d
	atf_check -o inline:'2\n' curtain -p d/2 ls d
	atf_check -o inline:'3\n' curtain -p d/3 ls d
	atf_check -o inline:'2\n3\n' curtain -p d -p d/1: ls d
	atf_check -o inline:'1\n3\n' curtain -p d -p d/2: ls d
	atf_check -o inline:'1\n2\n' curtain -p d -p d/3: ls d
}

atf_test_case filtered_ls_nested
filtered_ls_nested_body() {
	local p
	atf_check mkdir d
	atf_check touch d/1 d/2 d/3 d/x
	p='curtain -t curtain -p d/1 -p d/2 -p d/3'
	atf_check -o empty $p curtain -p d:li ls d
	atf_check -o inline:'1\n2\n3\n' $p curtain -p d ls d
	atf_check -o inline:'1\n2\n3\n' $p curtain -p d/1 -p d/2 -p d/3 ls d
	atf_check -o inline:'1\n' $p curtain -p d/1 ls d
	atf_check -o inline:'2\n' $p curtain -p d/2 ls d
	atf_check -o inline:'3\n' $p curtain -p d/3 ls d
	atf_check -o inline:'2\n3\n' $p curtain -p d -p d/1: ls d
	atf_check -o inline:'1\n3\n' $p curtain -p d -p d/2: ls d
	atf_check -o inline:'1\n2\n' $p curtain -p d -p d/3: ls d
}

atf_test_case sysctl_inherit
sysctl_inherit_body() {
	local n='security.curtain.enabled'
	atf_check -o save:works sysctl $n
	local works="atf_check -o file:works"
	local fails="atf_check -o empty"
	$fails curtain sysctl $n
	$fails curtain -t curtain \
		curtain -d ability:any_sysctl sysctl $n
	$works curtain -d ability:any_sysctl sysctl $n
	$works curtain -d sysctl:$n sysctl $n
	$works curtain -t curtain -d ability:any_sysctl \
		curtain -d ability:any_sysctl sysctl $n
	local a b
	for a in security.curtain.enabled security.curtain security
	do
		$fails curtain -t curtain \
			curtain -d sysctl:$a sysctl $n
		$fails curtain -t curtain -d ability:any_sysctl -d sysctl-deny:$a \
			curtain -d ability:any_sysctl sysctl $n
		$works curtain -d sysctl:$a sysctl $n
		$works curtain -t curtain -d ability:any_sysctl \
			curtain -d sysctl:$a sysctl $n
		$works curtain -t curtain -d sysctl:$a \
			curtain -d ability:any_sysctl sysctl $n
		for b in security.curtain.enabled security.curtain security
		do
			$fails curtain -t curtain -d ability:any_sysctl -d sysctl-deny:$a \
				curtain -d sysctl:$b sysctl $n
			$works curtain -t curtain -d sysctl:$a \
				curtain -d sysctl:$b sysctl $n
		done
	done
}

atf_test_case tmpdir_exec
tmpdir_exec_body() {
	cat > exec-script <<'EOF1'
f=$TMPDIR/test.sh
cat > $f <<'EOF2'
#!/bin/sh
echo TEST
EOF2
chmod +x $f
$f
e=$?
rm $f
exit $e
EOF1
	cat > exec-binary <<'EOF1'
f=$TMPDIR/test-echo
cp /bin/echo $f
$f TEST
e=$?
rm $f
exit $e
EOF1
	atf_check -s not-exit:0 -e not-empty curtain sh < exec-script
	atf_check -s not-exit:0 -e not-empty curtain sh < exec-binary
	atf_check -o inline:'TEST\n' curtain -t _tmpdir_shellexec sh < exec-script
	atf_check -s not-exit:0 -e not-empty curtain -t _tmpdir_shellexec sh < exec-binary
	atf_check -o inline:'TEST\n' curtain -t _tmpdir_exec sh < exec-script
	atf_check -o inline:'TEST\n' curtain -t _tmpdir_exec sh < exec-binary
}

atf_test_case append_only
append_only_body() {
	local p
	for p in d di dmi dmr
	do atf_check -s not-exit:0 -e not-empty curtain -p out:$p sh -c 'echo x > out'
	done
	atf_check test ! -e out
	atf_check curtain -p out:cm sh -c 'echo 1 > out'
	atf_check test -f out
	atf_check curtain -p out:p sh -c 'echo 2 >> out'
	for p in p pi pr cdp cdpi cdpr
	do
		atf_check -s not-exit:0 -e not-empty curtain -p out:$p sh -c 'echo x > out'
		atf_check -s not-exit:0 -e not-empty curtain -p out:$p truncate -s 0 out
	done
	atf_check curtain -p tmp:cp sh -c 'echo 3 >> tmp'
	atf_check curtain -p out:p -p tmp:r sh -c 'tee -a out < tmp > /dev/null'
	for p in c ci cr cm cmi cmr
	do atf_check -s not-exit:0 -e not-empty curtain -p out:$p sh -c 'unlink out'
	done
	atf_check test -f out
	atf_check -o inline:'1\n2\n3\n' cat out
	atf_check curtain -p out:di sh -c 'unlink out'
	atf_check test ! -e out
}

atf_test_case chroot cleanup
chroot_head() {
	atf_set require.user root
}
chroot_cleanup() {
	atf_check umount d/dev
}
chroot_body() {
	local jail_devfs_ruleset=4
	atf_check mkdir d
	atf_check mkdir d/dev
	atf_check mkdir d/bin
	atf_check mount -t devfs -o ruleset=$jail_devfs_ruleset devfs d/dev
	atf_check cp /rescue/echo d/bin
	atf_check -o inline:'test 1\n' curtain -d ability:chroot -f -p d:r -p d/bin:rx -S \
		chroot d echo "test 1"
	atf_check cp /rescue/sh d/bin
	atf_check -o inline:'test 2\n' curtain -d ability:chroot -f -p d:r -p d/bin:rx -p d/dev/stdout:w -S \
		chroot d sh -c 'echo "test 2" > /dev/stdout'
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
	atf_add_test_case unveil_dotdot
	atf_add_test_case reunveil_inheritance
	atf_add_test_case chflags
	atf_add_test_case chflags_system
	atf_add_test_case filtered_ls
	atf_add_test_case filtered_ls_nested
	atf_add_test_case sysctl_inherit
	atf_add_test_case tmpdir_exec
	atf_add_test_case append_only
	atf_add_test_case chroot
}

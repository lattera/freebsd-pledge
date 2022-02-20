#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <atf-c.h>
#include <err.h>
#include <pledge.h>

#include <netinet/in.h>
#include <sys/un.h>
#include <sys/socket.h>

#include "path-utils.h"

/* TODO: test socket ioctl() */
/* TODO: test getsockopt()/setsockopt() */

ATF_TC_WITHOUT_HEAD(socket_af_unix_allow);
ATF_TC_BODY(socket_af_unix_allow, tc)
{
	ATF_REQUIRE(pledge("stdio unix", "") >= 0);
	ATF_REQUIRE(socket(AF_LOCAL, SOCK_STREAM, 0) >= 0);
}

ATF_TC_WITHOUT_HEAD(socket_af_unix_deny);
ATF_TC_BODY(socket_af_unix_deny, tc)
{
	ATF_REQUIRE(pledge("stdio error", "") >= 0);
	ATF_CHECK_ERRNO(EPERM, socket(AF_LOCAL, SOCK_STREAM, 0) < 0);
}

ATF_TC_WITHOUT_HEAD(socket_af_inet_allow);
ATF_TC_BODY(socket_af_inet_allow, tc)
{
	ATF_REQUIRE(pledge("stdio inet", "") >= 0);
#ifdef AF_INET
	ATF_REQUIRE(socket(AF_INET, SOCK_STREAM, 0) >= 0);
#endif
#ifdef AF_INET6
	ATF_REQUIRE(socket(AF_INET6, SOCK_STREAM, 0) >= 0);
#endif
}

ATF_TC_WITHOUT_HEAD(socket_af_inet_deny);
ATF_TC_BODY(socket_af_inet_deny, tc)
{
	ATF_REQUIRE(pledge("stdio error", "") >= 0);
#ifdef AF_INET
	ATF_CHECK_ERRNO(EPERM, socket(AF_INET, SOCK_STREAM, 0) < 0);
#endif
#ifdef AF_INET6
	ATF_CHECK_ERRNO(EPERM, socket(AF_INET6, SOCK_STREAM, 0) < 0);
#endif
}

ATF_TC_WITHOUT_HEAD(socketpair_allow);
ATF_TC_BODY(socketpair_allow, tc)
{
	ATF_REQUIRE(pledge("stdio error", "") >= 0);
	/* socketpair() always allowed with just the "stdio" promise */
	int fds[2];
	ATF_REQUIRE(socketpair(AF_LOCAL, SOCK_STREAM, 0, fds) >= 0);
	ATF_CHECK(close(fds[0]) >= 0);
	ATF_CHECK(close(fds[1]) >= 0);
}

static const int basic_optnames[][2] = {
	{ SOL_SOCKET, SO_ERROR },
	{ SOL_SOCKET, SO_NOSIGPIPE },
};

static const int net_optnames[][2] = {
	{ SOL_SOCKET, SO_KEEPALIVE },
	{ SOL_SOCKET, SO_TIMESTAMP },
	{ SOL_SOCKET, SO_DOMAIN },
	{ SOL_SOCKET, SO_TYPE },
	{ SOL_SOCKET, SO_PROTOCOL },
	{ SOL_SOCKET, SO_PROTOTYPE },
};

ATF_TC_WITHOUT_HEAD(basic_sockopts_allow);
ATF_TC_BODY(basic_sockopts_allow, tc)
{
	int fd, val;
	ATF_REQUIRE((fd = socket(AF_LOCAL, SOCK_STREAM, 0)) >= 0);
	ATF_REQUIRE(pledge("stdio", "") >= 0);
	for (size_t i = 0; i < nitems(basic_optnames); i++) {
		socklen_t len = sizeof val;
		ATF_CHECK(getsockopt(fd, basic_optnames[i][0], basic_optnames[i][1], &val, &len) >= 0);
	}
}

ATF_TC_WITHOUT_HEAD(net_sockopts_allow);
ATF_TC_BODY(net_sockopts_allow, tc)
{
	int fd, val;
	ATF_REQUIRE((fd = socket(AF_LOCAL, SOCK_STREAM, 0)) >= 0);
	ATF_REQUIRE(pledge("stdio inet", "") >= 0);
	for (size_t i = 0; i < nitems(basic_optnames); i++) {
		socklen_t len = sizeof val;
		ATF_CHECK(getsockopt(fd, basic_optnames[i][0], basic_optnames[i][1], &val, &len) >= 0);
	}
	for (size_t i = 0; i < nitems(net_optnames); i++) {
		socklen_t len = sizeof val;
		ATF_CHECK(getsockopt(fd, net_optnames[i][0], net_optnames[i][1], &val, &len) >= 0);
	}
}

ATF_TC_WITHOUT_HEAD(net_sockopts_deny);
ATF_TC_BODY(net_sockopts_deny, tc)
{
	int fd, val;
	ATF_REQUIRE((fd = socket(AF_LOCAL, SOCK_STREAM, 0)) >= 0);
	ATF_REQUIRE(pledge("error stdio", "") >= 0);
	for (size_t i = 0; i < nitems(net_optnames); i++) {
		socklen_t len = sizeof val;
		ATF_CHECK_ERRNO(EPERM, getsockopt(fd, net_optnames[i][0], net_optnames[i][1], &val, &len) < 0);
	}
}


ATF_TC_WITHOUT_HEAD(ip_options_sockopt);
ATF_TC_BODY(ip_options_sockopt, tc)
{
	int fd;
	char buf[64];
	socklen_t len;
	ATF_REQUIRE((fd = socket(AF_INET, SOCK_STREAM, 0)) >= 0);
	ATF_CHECK(setsockopt(fd, IPPROTO_IP, IP_OPTIONS, NULL, 0) >= 0);
	ATF_CHECK(getsockopt(fd, IPPROTO_IP, IP_OPTIONS, buf, (len = sizeof buf, &len)) >= 0);
	ATF_REQUIRE(pledge("error stdio inet", "") >= 0);
	ATF_CHECK_ERRNO(EPERM, setsockopt(fd, IPPROTO_IP, IP_OPTIONS, NULL, 0) < 0);
	ATF_CHECK(getsockopt(fd, IPPROTO_IP, IP_OPTIONS, buf, (len = sizeof buf, &len)) >= 0);
	ATF_CHECK(close(fd) >= 0);
}


static int
fd_cmp(int fd0, int fd1)
{
	struct stat st0, st1;
	int r;
	r = fstat(fd0, &st0);
	if (r < 0)
		err(1, "fstat");
	r = fstat(fd1, &st1);
	if (r < 0)
		err(1, "fstat");
	return (st0.st_dev == st1.st_dev && st0.st_ino == st1.st_ino ? 0 : 1);
}

static int
send_fd(int sock_fd, int pass_fd)
{
	struct msghdr msg;
	union { /* for alignment */
		struct cmsghdr cmsg;
		char buf[CMSG_SPACE(sizeof pass_fd)];
	} u;
	msg = (struct msghdr){
		.msg_control = &u.cmsg,
		.msg_controllen = sizeof u,
	};
	u.cmsg = (struct cmsghdr){
		.cmsg_level = SOL_SOCKET,
		.cmsg_type = SCM_RIGHTS,
		.cmsg_len = CMSG_LEN(sizeof pass_fd),
	};
	memcpy(CMSG_DATA(&u.cmsg), &pass_fd, sizeof pass_fd);
	return (sendmsg(sock_fd, &msg, 0));
}

static int
recv_fd(int sock_fd)
{
	int pass_fd, r;
	struct msghdr msg;
	union { /* for alignment */
		struct cmsghdr cmsg;
		char buf[CMSG_SPACE(sizeof pass_fd)];
	} u;
	msg = (struct msghdr){
		.msg_control = &u.cmsg,
		.msg_controllen = sizeof u,
	};
	r = recvmsg(sock_fd, &msg, 0);
	if (r < 0)
		return (r);
	if (!(msg.msg_control == &u.cmsg))
		errx(1, "no control msg");
	if (u.cmsg.cmsg_level != SOL_SOCKET ||
	    u.cmsg.cmsg_type != SCM_RIGHTS)
		errx(1, "unexpected control msg");
	if (u.cmsg.cmsg_len != CMSG_LEN(sizeof pass_fd))
		errx(1, "wrong len control msg");
	memcpy(&pass_fd, CMSG_DATA(&u.cmsg), sizeof pass_fd);
	return (pass_fd);
}

ATF_TC_WITHOUT_HEAD(pass_fd_same_proc);
ATF_TC_BODY(pass_fd_same_proc, tc)
{
	int sock_fds[2], fd0, fd1;
	ATF_REQUIRE(pledge("stdio error sendfd recvfd", "") >= 0);
	ATF_REQUIRE((fd0 = open("/dev/null", O_RDONLY)) >= 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sock_fds) >= 0);
	ATF_REQUIRE(send_fd(sock_fds[1], fd0) >= 0);
	ATF_REQUIRE((fd1 = recv_fd(sock_fds[0])) >= 0);
	ATF_CHECK(fd_cmp(fd0, fd1) == 0);
	ATF_CHECK(close(sock_fds[0]) >= 0);
	ATF_CHECK(close(sock_fds[1]) >= 0);
	ATF_CHECK(close(fd0) >= 0);
	ATF_CHECK(close(fd1) >= 0);
}

ATF_TC_WITHOUT_HEAD(pass_fd_dir_deny);
ATF_TC_BODY(pass_fd_dir_deny, tc)
{
	int sock_fds[2], fd;
	ATF_REQUIRE(pledge("stdio error rpath sendfd recvfd", "") >= 0);
	ATF_REQUIRE((fd = open(".", O_RDONLY)) >= 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sock_fds) >= 0);
	ATF_CHECK_ERRNO(EPERM, send_fd(sock_fds[1], fd) < 0);
	ATF_CHECK(close(sock_fds[0]) >= 0);
	ATF_CHECK(close(sock_fds[1]) >= 0);
	ATF_CHECK(close(fd) >= 0);
}

static void
test_pass_fd_fork(bool allow_send, bool allow_recv)
{
	int sock_fds[2], pass_fd;
	pid_t sender_pid, receiver_pid;
	ATF_REQUIRE((pass_fd = open("/dev/null", O_RDONLY)) >= 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sock_fds) >= 0);
	sender_pid = atf_utils_fork();
	if (sender_pid == 0) {
		int r;
		ATF_REQUIRE(pledge(allow_send ? "stdio sendfd" : "stdio error", "") >= 0);
		r = send_fd(sock_fds[1], pass_fd);
		exit(r < 0 ? 1 : 0);
	}
	atf_utils_wait(sender_pid, allow_send ? 0 : 1, "", "");
	if (allow_send) {
		receiver_pid = atf_utils_fork();
		if (receiver_pid == 0) {
			int r;
			ATF_REQUIRE(pledge(allow_recv ? "stdio recvfd" : "stdio error", "") >= 0);
			r = recv_fd(sock_fds[0]);
			exit(r < 0 ? 1 : fd_cmp(pass_fd, r) != 0 ? 2 : 0);
		}
		atf_utils_wait(receiver_pid, allow_recv ? 0 : 1, "", "");
	}
}

ATF_TC_WITHOUT_HEAD(pass_fd_both_allow);
ATF_TC_BODY(pass_fd_both_allow, tc)
{
	test_pass_fd_fork(true, true);
}

ATF_TC_WITHOUT_HEAD(pass_fd_send_deny);
ATF_TC_BODY(pass_fd_send_deny, tc)
{
	test_pass_fd_fork(false, true);
}

ATF_TC_WITHOUT_HEAD(pass_fd_recv_deny);
ATF_TC_BODY(pass_fd_recv_deny, tc)
{
	test_pass_fd_fork(true, false);
}


ATF_TC_WITHOUT_HEAD(unix_bind_allow);
ATF_TC_BODY(unix_bind_allow, tc)
{
	struct sockaddr_un un = { .sun_family = AF_UNIX, .sun_path = "test.sock" };
	int fd;
	ATF_REQUIRE((fd = socket(AF_UNIX, SOCK_STREAM, 0)) >= 0);
	ATF_REQUIRE(pledge("stdio unix", "") >= 0);
	ATF_CHECK(bind(fd, (void *)&un, sizeof un) >= 0);
	ATF_CHECK(listen(fd, 0) >= 0);
	ATF_CHECK(unlink(un.sun_path) >= 0);
}

ATF_TC_WITHOUT_HEAD(unix_bind_deny);
ATF_TC_BODY(unix_bind_deny, tc)
{
	struct sockaddr_un un = { .sun_family = AF_UNIX, .sun_path = "test.sock" };
	int fd;
	ATF_REQUIRE((fd = socket(AF_UNIX, SOCK_STREAM, 0)) >= 0);
	ATF_REQUIRE(pledge("stdio error", "") >= 0);
	ATF_CHECK_ERRNO(EPERM, bind(fd, (void *)&un, sizeof un) < 0);
}

ATF_TC_WITHOUT_HEAD(unix_connect_allow);
ATF_TC_BODY(unix_connect_allow, tc)
{
	struct sockaddr_un un = { .sun_family = AF_UNIX, .sun_path = "test.sock" };
	int fd0, fd1;
	ATF_REQUIRE((fd0 = socket(AF_UNIX, SOCK_STREAM, 0)) >= 0);
	ATF_REQUIRE((fd1 = socket(AF_UNIX, SOCK_STREAM, 0)) >= 0);
	ATF_CHECK(bind(fd0, (void *)&un, sizeof un) >= 0);
	ATF_CHECK(listen(fd0, 0) >= 0);
	ATF_REQUIRE(pledge("stdio unix", "") >= 0);
	ATF_CHECK(connect(fd1, (void *)&un, sizeof un) >= 0);
}

ATF_TC_WITHOUT_HEAD(unix_connect_deny);
ATF_TC_BODY(unix_connect_deny, tc)
{
	struct sockaddr_un un = { .sun_family = AF_UNIX, .sun_path = "test.sock" };
	int fd0, fd1;
	ATF_REQUIRE((fd0 = socket(AF_UNIX, SOCK_STREAM, 0)) >= 0);
	ATF_REQUIRE((fd1 = socket(AF_UNIX, SOCK_STREAM, 0)) >= 0);
	ATF_CHECK(bind(fd0, (void *)&un, sizeof un) >= 0);
	ATF_CHECK(listen(fd0, 0) >= 0);
	ATF_REQUIRE(pledge("stdio error", "") >= 0);
	ATF_CHECK_ERRNO(EPERM, connect(fd1, (void *)&un, sizeof un) < 0);
}

ATF_TC_WITHOUT_HEAD(pledge_unix_still_somewhat_hides_fs);
ATF_TC_BODY(pledge_unix_still_somewhat_hides_fs, tc)
{
	ATF_REQUIRE(pledge("stdio unix", "") >= 0);
	check_access("/", "dse");
	check_access(".", "dse");
}


ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, socket_af_unix_allow);
	ATF_TP_ADD_TC(tp, socket_af_unix_deny);
	ATF_TP_ADD_TC(tp, socket_af_inet_allow);
	ATF_TP_ADD_TC(tp, socket_af_inet_deny);
	ATF_TP_ADD_TC(tp, socketpair_allow);
	ATF_TP_ADD_TC(tp, basic_sockopts_allow);
	ATF_TP_ADD_TC(tp, net_sockopts_allow);
	ATF_TP_ADD_TC(tp, net_sockopts_deny);
	ATF_TP_ADD_TC(tp, ip_options_sockopt);
	ATF_TP_ADD_TC(tp, pass_fd_same_proc);
	ATF_TP_ADD_TC(tp, pass_fd_dir_deny);
	ATF_TP_ADD_TC(tp, pass_fd_both_allow);
	ATF_TP_ADD_TC(tp, pass_fd_send_deny);
	ATF_TP_ADD_TC(tp, pass_fd_recv_deny);
	ATF_TP_ADD_TC(tp, unix_bind_allow);
	ATF_TP_ADD_TC(tp, unix_bind_deny);
	ATF_TP_ADD_TC(tp, unix_connect_allow);
	ATF_TP_ADD_TC(tp, unix_connect_deny);
	ATF_TP_ADD_TC(tp, pledge_unix_still_somewhat_hides_fs);
	return (atf_no_error());
}

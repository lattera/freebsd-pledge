#include <stdio.h>
#include <atf-c.h>
#include <stdio.h>
#include <pledge.h>

#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/nameser.h>
#include <resolv.h>

ATF_TC_WITHOUT_HEAD(gethostbyname_localhost);
ATF_TC_BODY(gethostbyname_localhost, tc)
{
	struct hostent *he;
	ATF_REQUIRE(pledge("stdio dns", "") >= 0);
	ATF_REQUIRE((he = gethostbyname("localhost")));
	ATF_CHECK_STREQ("localhost", he->h_name);
}

ATF_TC_WITHOUT_HEAD(getprotobyname_tcp);
ATF_TC_BODY(getprotobyname_tcp, tc)
{
	struct protoent *pe;
	ATF_REQUIRE(pledge("stdio dns", "") >= 0);
	ATF_REQUIRE((pe = getprotobyname("tcp")));
	ATF_CHECK_STREQ("tcp", pe->p_name);
}

ATF_TC_WITHOUT_HEAD(getservbyname_ssh);
ATF_TC_BODY(getservbyname_ssh, tc)
{
	struct servent *se;
	ATF_REQUIRE(pledge("stdio dns", "") >= 0);
	ATF_REQUIRE((se = getservbyname("ssh", "tcp")));
	ATF_CHECK_STREQ("ssh", se->s_name);
}

ATF_TC_WITHOUT_HEAD(resolv_resinit);
ATF_TC_BODY(resolv_resinit, tc)
{
	ATF_REQUIRE(pledge("stdio dns", "") >= 0);
	ATF_REQUIRE(res_init() >= 0);
}

ATF_TC_WITHOUT_HEAD(getaddrinfo_localhost);
ATF_TC_BODY(getaddrinfo_localhost, tc)
{
	struct addrinfo *ai;
	bool found;
	ATF_REQUIRE(pledge("stdio dns", "") >= 0);
	ATF_REQUIRE(getaddrinfo("localhost", NULL, NULL, &ai) >= 0);
	found = false;
	for (struct addrinfo *e = ai; e; e = e->ai_next)
		switch (e->ai_family) {
#ifdef AF_INET
		case AF_INET: {
			struct sockaddr_in *in = (void *)e->ai_addr;
			if (ntohl(in->sin_addr.s_addr) == INADDR_LOOPBACK)
				found = true;
			break;
		}
#endif
#ifdef AF_INET6
		case AF_INET6: {
			struct sockaddr_in6 *in = (void *)e->ai_addr;
			if (memcmp(&in->sin6_addr, &in6addr_loopback, sizeof in6addr_loopback) == 0)
				found = true;
			break;
		}
#endif
		}
	ATF_CHECK(found);
	freeaddrinfo(ai);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, gethostbyname_localhost);
	ATF_TP_ADD_TC(tp, getprotobyname_tcp);
	ATF_TP_ADD_TC(tp, getservbyname_ssh);
	ATF_TP_ADD_TC(tp, resolv_resinit);
	ATF_TP_ADD_TC(tp, getaddrinfo_localhost);
	return (atf_no_error());
}

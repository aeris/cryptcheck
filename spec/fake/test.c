#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int debug(const char *fmt, ...) {
//	return 0;
	va_list arg;
	va_start(arg, fmt);
	int result = vfprintf(stderr, fmt, arg);
	va_end(arg);
	fflush(stderr);
	return result;
}

void debug_saddr(const int family, const void *saddr) {
	char buff[INET6_ADDRSTRLEN];
	const void *addr;
	switch (family) {
		case AF_INET:;
			const struct sockaddr_in *s4 = saddr;
			debug("    family: %d\n", s4->sin_family);
			debug("    port: %d\n", s4->sin_port);
			addr = &(s4->sin_addr);
			break;
		case AF_INET6:;
			const struct sockaddr_in6 *s6 = saddr;
			debug("    family: %d\n", s6->sin6_family);
			debug("    port: %d\n", s6->sin6_port);
			debug("    flowinfo: %d\n", s6->sin6_flowinfo);
			debug("    scope: %d\n", s6->sin6_scope_id);
			addr = &(s6->sin6_addr);
			break;
	}

	inet_ntop(family, addr, buff, INET6_ADDRSTRLEN);
	debug("    addr: %p, %s\n", saddr, buff);
}

void debug_addr(const struct addrinfo *addr) {
	debug("addrinfo: %p\n", addr);
	debug("  flags: %d\n", addr->ai_flags);
	debug("  family: %d\n", addr->ai_family);
	debug("  type: %d\n", addr->ai_socktype);
	debug("  protocol: %d\n", addr->ai_protocol);
	debug("  len: %d\n", addr->ai_addrlen);
	if (addr->ai_addrlen > 0) debug_saddr(addr->ai_family, addr->ai_addr);
	debug("  name: %s\n", addr->ai_canonname);
	debug("  next: %p\n", addr->ai_next);
}

void debug_addrinfo(const struct addrinfo *addr) {
	for (const struct addrinfo *rp = addr; rp != NULL; rp = rp->ai_next) {
		debug_addr(rp);
	}
}

int main(int argc, char *argv[]) {
	struct addrinfo hints;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM; /* Datagram socket */
	hints.ai_flags = 0;    /* For wildcard IP address */
	hints.ai_protocol = 0;          /* Any protocol */
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

    struct addrinfo *result;
    debug("Before result: result=%p\n", &result);
	const int s = getaddrinfo("localhost", NULL, &hints, &result);
	if (s != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
		exit(EXIT_FAILURE);
	}

	debug("The result: result=%p\n", result);
	debug_addrinfo(result);
}

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdbool.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "fake.h"

bool frozen = false;
time_t frozen_time = 0;
static time_t (*libc_time)(time_t*);

void _freeze(const time_t time) {
	frozen_time = time;
	frozen = true;
}

void _unfreeze() {
	frozen = false;
}

time_t time(time_t *arg) {
	if (frozen) {
		if (arg) *arg = frozen_time;
		return frozen_time;
	} else {
		time_t time = libc_time(arg);
		return time;
	}
}

typedef struct ip_t {
	int af;
	void *addr;
} ip_t;
typedef struct host_t {
	char *host;
	size_t size;
	ip_t **ips;
} host_t;
host_t *mocked_host = NULL;

static int (*libc_getaddrinfo)(const char*, const char*,
	const struct addrinfo *, struct addrinfo **);

static void free_mocked_host() {
	if (mocked_host == NULL) return;
	for (size_t n =0; n < mocked_host->size; ++n ) {
		ip_t *ip = mocked_host->ips[n];
		free(ip->addr);
		free(ip);
	}
	free(mocked_host->ips);
	free(mocked_host->host);
	free(mocked_host);
	mocked_host = NULL;
}

void _mock_getaddrinfo(const char *host, const size_t size, ...) {
	free_mocked_host();

	host_t *mocked = malloc(sizeof(*mocked));
	mocked->host = strdup(host);
	mocked->size = size;
	ip_t **ips = malloc(size * sizeof(*ips));

	va_list args;
	va_start(args, size);

	for (size_t n = 0; n < size; ++n) {
		char *arg = va_arg(args, char*);
		ip_t *ip = malloc(sizeof(*ip));
		int family;
		void *addr, *saddr;
		if (strstr(arg, ".") != NULL) {
			family = AF_INET;
			struct sockaddr_in *s4 = malloc(sizeof(*s4));
			s4->sin_family = family;
			s4->sin_port = 0;
			saddr = s4;
			addr = &(s4->sin_addr);
		} else if (strstr(arg, ":") != NULL) {
			family = AF_INET6;
			struct sockaddr_in6 *s6 = malloc(sizeof(*s6));
			s6->sin6_family = family;
			s6->sin6_port = 0;
			s6->sin6_flowinfo = 0;
			s6->sin6_scope_id = 0;
			saddr = s6;
			addr = &(s6->sin6_addr);
		} else {
			fprintf(stderr, "Invalid IP format: %s\n", arg);
			exit(-1);
		}
		inet_pton(family, arg, addr);

		ip->af = family;
		ip->addr = saddr;

		ips[n] = ip;
	}

	va_end(args);

	mocked->ips = ips;
	mocked_host = mocked;
}

void _unmock_getaddrinfo() {
	free_mocked_host();
}

typedef struct socktype_t {
	int type;
	int protocol;
} socktype_t;
const socktype_t SOCK_TYPES[] = {
	{ .type = SOCK_STREAM, .protocol = IPPROTO_TCP },
	{ .type = SOCK_DGRAM, .protocol = IPPROTO_UDP },
	{ .type = SOCK_RAW, .protocol = IPPROTO_IP }
};
const size_t SOCK_TYPES_SIZE = sizeof(SOCK_TYPES)/sizeof(socktype_t);

int get_port_from_service(const char *service) {
	if (service == NULL) return 0;

	struct servent* servent = getservbyname(service, NULL);
	int port;
	if (servent == NULL) {
		port = htons(atoi(service));
	} else {
		port = servent->s_port;
		free(servent);
	}

	return port;
}

int getaddrinfo(const char *node, const char *service,
	const struct addrinfo *hints, struct addrinfo **res) {
	const int port = get_port_from_service(service);

	if (mocked_host == NULL || strcmp(node, mocked_host->host) != 0)
		return libc_getaddrinfo(node, service, hints, res);

	size_t size = mocked_host->size;
	struct addrinfo *addr = NULL, *previous = NULL;
	for (size_t n = 0; n < size; ++n) {
		const ip_t *ip = mocked_host->ips[n];

		for ( size_t m = 0; m < SOCK_TYPES_SIZE; ++m) {
			const socktype_t type = SOCK_TYPES[m];

			if ( (hints->ai_socktype != 0 && hints->ai_socktype != type.type) ||
					(hints->ai_protocol != 0 && hints->ai_protocol != type.protocol) ) {
				continue;
			}

			addr = malloc(sizeof(*addr));
			addr->ai_flags = hints->ai_flags;
			addr->ai_family = ip->af;
			addr->ai_socktype = type.type;
			addr->ai_protocol = type.protocol;

			size_t len;
			void *ai_addr;
			switch (addr->ai_family) {
				case AF_INET:;
					struct sockaddr_in *ai_addr4;
					len = sizeof(*ai_addr4);
					ai_addr4 = malloc(len);
					ai_addr = ai_addr4;
					memcpy(ai_addr4, ip->addr, len);
					ai_addr4->sin_port = port;
					break;
				case AF_INET6:;
					struct sockaddr_in6 *ai_addr6;
					len = sizeof(*ai_addr6);
					ai_addr6 = malloc(len);
					ai_addr = ai_addr6;
					memcpy(ai_addr6, ip->addr, len);
					ai_addr6->sin6_port = port;
					break;
			}
			addr->ai_addrlen = len;
			addr->ai_addr = ai_addr;
			addr->ai_canonname = NULL;
			addr->ai_next = previous;
			previous = addr;
		}
	}

	*res = addr;

	return 0;
}

static void __attribute__((constructor)) setup() {
	char *error = dlerror();
	*(void **) (&libc_time) = dlsym(RTLD_NEXT, "time");
	if ((error = dlerror()) != NULL) {
		fprintf(stderr, "%s\n", error);
	}
	*(void **) (&libc_getaddrinfo) = dlsym(RTLD_NEXT, "getaddrinfo");
	if ((error = dlerror()) != NULL) {
		fprintf(stderr, "%s\n", error);
	}
}

static void __attribute__((destructor)) teardown() {
	free_mocked_host();
}

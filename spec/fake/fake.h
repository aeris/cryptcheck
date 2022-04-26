#include <time.h>

void _freeze(const time_t time);
void _unfreeze();

void _mock_getaddrinfo(const char *host, const size_t size, ...);
void _unmock_getaddrinfo();

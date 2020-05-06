RBENV_ROOT ?= ~/.rbenv
RBENV__VERSION := v1.1.2
RUBY_BUILD_VERSION = v20200401

OPENSSL_1_0_VERSION = 1.0.2j
OPENSSL_1_1_VERSION = 1.1.1g

RUBY_1_0_VERSION = 2.3.8
RUBY_1_1_VERSION = 2.6.6

ROOT_DIR = $(dir $(realpath $(firstword $(MAKEFILE_LIST))))
BUILD_DIR = $(ROOT_DIR)/build

LIBRARY_PATH_1_0   = $(BUILD_DIR)/openssl-$(OPENSSL_1_0_VERSION)
C_INCLUDE_PATH_1_0 = $(LIBRARY_PATH_1_0)/include
LIBRARY_PATH_1_1   = $(BUILD_DIR)/openssl-$(OPENSSL_1_1_VERSION)
C_INCLUDE_PATH_1_1 = $(LIBRARY_PATH_1_1)/include

MAKE_OPTS ?= -j $(shell nproc)

.SECONDARY:

clean:
	rm -rf build/

$(RBENV_ROOT)/:
	git clone https://github.com/rbenv/rbenv/ "$@" -b "$(RBENV__VERSION)" --depth 1
$(RBENV_ROOT)/plugins/ruby-build/: | $(RBENV_ROOT)/
	git clone https://github.com/rbenv/ruby-build/ "$@" -b "$(RUBY_BUILD_VERSION)" --depth 1
rbenv: | $(RBENV_ROOT)/plugins/ruby-build/

build/:
	mkdir "$@"

build/chacha-poly.patch: | build/
	wget -q https://github.com/cloudflare/sslconfig/raw/master/patches/openssl__chacha20_poly1305_draft_and_rfc_ossl102j.patch -O "$@"

build/openssl-%.tar.gz: | build/
	wget -q "https://www.openssl.org/source/$(notdir $@)" -O "$@"

build/openssl-$(OPENSSL_1_0_VERSION)/: build/openssl-$(OPENSSL_1_0_VERSION).tar.gz build/chacha-poly.patch
	tar -C build -xf "$<"
	patch -d "$@" -p1 < build/chacha-poly.patch
	for p in patches/openssl/*.patch; do patch -d "$@" -p1 < "$$p"; done

build/openssl-$(OPENSSL_1_1_VERSION)/: build/openssl-$(OPENSSL_1_1_VERSION).tar.gz build/chacha-poly.patch
	tar -C build -xf "$<"

.ONESHELL:
build/openssl-%/Makefile: | build/openssl-%/
	cd "$(dir $@)"
	./config --prefix=/usr --openssldir=/etc/ssl \
		enable-ssl2 enable-ssl3 enable-ssl3-method \
		enable-md2 enable-rc5 enable-weak-ssl-ciphers enable-shared
	$(MAKE) $(MAKE_OPTS) depend

build/openssl-%/libssl.so build/openssl-%/libcrypto.so: build/openssl-%/Makefile
	$(MAKE) -C "$(dir $<)" $(MAKE_OPTS)

openssl-1.0: build/openssl-$(OPENSSL_1_0_VERSION)/libssl.so build/openssl-$(OPENSSL_1_0_VERSION)/libcrypto.so
openssl-1.1: build/openssl-$(OPENSSL_1_1_VERSION)/libssl.so build/openssl-$(OPENSSL_1_1_VERSION)/libcrypto.so
openssl: openssl-1.0 openssl-1.1

build/$(RUBY_1_0_VERSION)-cryptcheck: $(RBENV_ROOT)/plugins/ruby-build/share/ruby-build/$(RUBY_1_0_VERSION)
	cp "$<" "$@"
build/$(RUBY_1_1_VERSION)-cryptcheck: $(RBENV_ROOT)/plugins/ruby-build/share/ruby-build/$(RUBY_1_1_VERSION)
	cp "$<" "$@"

$(RBENV_ROOT)/versions/$(RUBY_1_0_VERSION)-cryptcheck: build/$(RUBY_1_0_VERSION)-cryptcheck openssl-1.0
	cat patches/ruby/*.patch | \
	LIBRARY_PATH="$(LIBRARY_PATH_1_0)" \
	C_INCLUDE_PATH="$(C_INCLUDE_PATH_1_0)" \
	LD_LIBRARY_PATH="$(LIBRARY_PATH_1_0)" \
	RUBY_BUILD_CACHE_PATH="$(BUILD_DIR)" \
	RUBY_BUILD_DEFINITIONS="$(BUILD_DIR)" \
	MAKE_OPTS="$(MAKE_OPTS)" rbenv install -fp "$(notdir $@)"
$(RBENV_ROOT)/versions/$(RUBY_1_1_VERSION)-cryptcheck: build/$(RUBY_1_1_VERSION)-cryptcheck openssl-1.1
	cat patches/ciphersuites.patch | \
	LIBRARY_PATH="$(LIBRARY_PATH_1_1)" \
	C_INCLUDE_PATH="$(C_INCLUDE_PATH_1_1)" \
	LD_LIBRARY_PATH="$(LIBRARY_PATH_1_1)" \
	RUBY_BUILD_CACHE_PATH="$(BUILD_DIR)" \
	RUBY_BUILD_DEFINITIONS="$(BUILD_DIR)" \
	MAKE_OPTS="$(MAKE_OPTS)" rbenv install -fp "$(notdir $@)"
ruby-1.0: $(RBENV_ROOT)/versions/$(RUBY_1_0_VERSION)-cryptcheck
ruby-1.1: $(RBENV_ROOT)/versions/$(RUBY_1_1_VERSION)-cryptcheck
ruby: ruby-1.0 ruby-1.1

build/libfaketime.so: spec/faketime/faketime.c spec/faketime/faketime.h
	$(CC) $^ -o "$@" -shared -fPIC -ldl -std=c99 -Werror -Wall
faketime: build/libfaketime.so
.PHONY: faketime

test-material:
	bin/generate-test-material.rb

test: spec/faketime/libfaketime.so
	LD_LIBRARY_PATH="$(LIBRARY_PATH_1_0):$(BUILD_DIR)" bin/rspec
.PHONY: test

docker-1.0:
	docker build . --target engine \
		-t aeris22/cryptcheck:v2-1.0 \
		-t aeris22/cryptcheck:v2.2-1.0 \
		-t aeris22/cryptcheck:latest-1.0 \
		-t aeris22/cryptcheck:v2 \
		-t aeris22/cryptcheck:v2.2 \
		-t aeris22/cryptcheck:latest
docker-1.1:
	docker build . --target engine \
		--build-arg OPENSSL_VERSION=1.1.1g \
		--build-arg OPENSSL_BINDING=1.1 \
		--build-arg OPENSSL_LIB_VERSION=1.1 \
		--build-arg RUBY_VERSION=2.6.6-cryptcheck \
		-t aeris22/cryptcheck:v2-1.1 \
		-t aeris22/cryptcheck:v2.2-1.1 \
		-t aeris22/cryptcheck:latest-1.1
docker: docker-1.0 docker-1.1

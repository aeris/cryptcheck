ROOT_DIR := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))
BUILD_DIR := $(ROOT_DIR)/build

export RBENV_ROOT ?= $(ROOT_DIR)/build/rbenv
_RBENV_VERSION := v1.3.0
RUBY_BUILD_VERSION = v20240917

OPENSSL_1_0_VERSION := 1.0.2j
OPENSSL_1_1_VERSION := 1.1.1g

RUBY_1_0_VERSION := 2.3.8
RUBY_1_1_VERSION := 2.6.9

LIBRARY_PATH_1_0   := $(BUILD_DIR)/openssl-$(OPENSSL_1_0_VERSION)/lib
C_INCLUDE_PATH_1_0 := $(BUILD_DIR)/openssl-$(OPENSSL_1_0_VERSION)/include
LIBRARY_PATH_1_1   := $(BUILD_DIR)/openssl-$(OPENSSL_1_1_VERSION)/lib
C_INCLUDE_PATH_1_1 := $(BUILD_DIR)/openssl-$(OPENSSL_1_1_VERSION)/include

MAKE_OPTS ?= -j $(shell nproc)

export CC := ccache gcc
export CXX := ccache g++

export RUBY_CONFIGURE_OPTS := --disable-install-doc

.SUFFIXES:
.SECONDARY:

.DEFAULT_GOAL := all
all:
	$(MAKE) clean
	$(MAKE) openssl
	$(MAKE) rbenv
	$(MAKE) ruby
	$(MAKE) fake
.PHONY: all

clean:
	rm -rf build/

$(RBENV_ROOT)/:
	git clone https://github.com/rbenv/rbenv/ "$@" -b "$(_RBENV_VERSION)" --depth 1
$(RBENV_ROOT)/plugins/ruby-build/: | $(RBENV_ROOT)/
	git clone https://github.com/rbenv/ruby-build/ "$@" -b "$(RUBY_BUILD_VERSION)" --depth 1
rbenv: | $(RBENV_ROOT)/plugins/ruby-build/

build/:
	mkdir -p "$@"

build/chacha-poly.patch: | build/
	wget -q https://github.com/cloudflare/sslconfig/raw/master/patches/openssl__chacha20_poly1305_draft_and_rfc_ossl102j.patch -O "$@"

build/openssl-%.tar.gz: | build/
	wget -q "https://www.openssl.org/source/$(notdir $@)" -O "$@"

build/openssl-$(OPENSSL_1_0_VERSION)/src/: build/openssl-$(OPENSSL_1_0_VERSION).tar.gz  build/chacha-poly.patch
	mkdir -p "$@"
	tar -C "$@" --strip-components=1 -xf "$<"
	patch -d "$@" -p1 < build/chacha-poly.patch
	for p in patches/openssl/*.patch; do patch -d "$@" -p1 < "$$p"; done

build/openssl-$(OPENSSL_1_1_VERSION)/src/: build/openssl-$(OPENSSL_1_1_VERSION).tar.gz
	mkdir -p "$@"
	tar -C "$@" --strip-components=1 -xf "$<"

.ONESHELL:
build/openssl-%/src/Makefile: | build/openssl-%/src/
	cd "$(dir $@)"
	./config --prefix="$(BUILD_DIR)/openssl-$*" --openssldir="$(BUILD_DIR)/openssl-$*" \
		enable-ssl2 enable-ssl3 enable-ssl3-method \
		enable-md2 enable-rc5 enable-weak-ssl-ciphers enable-shared
	# $(MAKE) $(MAKE_OPTS) depend

build/openssl-%/src/libssl.so: build/openssl-%/src/Makefile
	$(MAKE) -C "$(dir $<)" $(MAKE_OPTS)

build/openssl-%/lib/libssl.so: build/openssl-%/src/libssl.so
	$(MAKE) -C "$(dir $<)" $(MAKE_OPTS) install

openssl-1.0: build/openssl-$(OPENSSL_1_0_VERSION)/lib/libssl.so
openssl-1.1: build/openssl-$(OPENSSL_1_1_VERSION)/lib/libssl.so
openssl: openssl-1.0 openssl-1.1

build/$(RUBY_1_0_VERSION)-cryptcheck: $(RBENV_ROOT)/plugins/ruby-build/share/ruby-build/$(RUBY_1_0_VERSION) | build/
	cp "$<" "$@"
build/$(RUBY_1_1_VERSION)-cryptcheck: $(RBENV_ROOT)/plugins/ruby-build/share/ruby-build/$(RUBY_1_1_VERSION) | build/
	cp "$<" "$@"

$(RBENV_ROOT)/versions/$(RUBY_1_0_VERSION)-cryptcheck/lib/ruby/2.3.0/rubygems/ssl_certs/GlobalSignRootCA_R3.pem \
$(RBENV_ROOT)/versions/$(RUBY_1_1_VERSION)-cryptcheck/lib/ruby/2.6.0/rubygems/ssl_certs/GlobalSignRootCA_R3.pem:
	mkdir -p "$(dir $@)"
	wget https://raw.githubusercontent.com/rubygems/rubygems/master/lib/rubygems/ssl_certs/rubygems.org/GlobalSignRootCA_R3.pem -O "$@"

$(RBENV_ROOT)/versions/$(RUBY_1_0_VERSION)-cryptcheck: build/$(RUBY_1_0_VERSION)-cryptcheck \
	 $(RBENV_ROOT)/versions/$(RUBY_1_0_VERSION)-cryptcheck/lib/ruby/2.3.0/rubygems/ssl_certs/GlobalSignRootCA_R3.pem \
	 openssl-1.0
	cat patches/ruby/*.patch | \
	LIBRARY_PATH="$(LIBRARY_PATH_1_0)" \
	C_INCLUDE_PATH="$(C_INCLUDE_PATH_1_0)" \
	LD_LIBRARY_PATH="$(LIBRARY_PATH_1_0)" \
	RUBY_BUILD_CACHE_PATH="$(BUILD_DIR)" \
	RUBY_BUILD_DEFINITIONS="$(BUILD_DIR)" \
	MAKE_OPTS="$(MAKE_OPTS)" $(RBENV_ROOT)/bin/rbenv install -fp "$(notdir $@)"
$(RBENV_ROOT)/versions/$(RUBY_1_1_VERSION)-cryptcheck: build/$(RUBY_1_1_VERSION)-cryptcheck \
	$(RBENV_ROOT)/versions/$(RUBY_1_1_VERSION)-cryptcheck/lib/ruby/2.6.0/rubygems/ssl_certs/GlobalSignRootCA_R3.pem openssl-1.1
	cat patches/ciphersuites.patch | \
	LIBRARY_PATH="$(LIBRARY_PATH_1_1)" \
	C_INCLUDE_PATH="$(C_INCLUDE_PATH_1_1)" \
	LD_LIBRARY_PATH="$(LIBRARY_PATH_1_1)" \
	RUBY_BUILD_CACHE_PATH="$(BUILD_DIR)" \
	RUBY_BUILD_DEFINITIONS="$(BUILD_DIR)" \
	MAKE_OPTS="$(MAKE_OPTS)" $(RBENV_ROOT)/bin/rbenv install -fp "$(notdir $@)"
ruby-1.0: $(RBENV_ROOT)/versions/$(RUBY_1_0_VERSION)-cryptcheck
ruby-1.1: $(RBENV_ROOT)/versions/$(RUBY_1_1_VERSION)-cryptcheck
ruby: ruby-1.0 ruby-1.1

build/libfake.so: spec/fake/fake.c spec/fake/fake.h
	LANG=C $(CC) $^ -g -o "$@" -shared -fPIC -ldl -std=c99 -Werror -Wall -pedantic
fake: build/libfake.so

build/test: spec/fake/test.c
	LANG=C $(CC) $^ -g -o "$@" -Werror -Wall -pedantic

test-material:
	bin/generate-test-material.rb

test: build/libfake.so
	LD_LIBRARY_PATH="$(LIBRARY_PATH_1_0):$(BUILD_DIR)" LD_PRELOAD="$(ROOT_DIR)/$^" bin/rspec
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

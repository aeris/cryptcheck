PWD = $(shell pwd)
OPENSSL_LIB_VERSION = 1.0.0
OPENSSL_VERSION = 1.0.2j
OPENSSL_NAME = openssl-$(OPENSSL_VERSION)
OPENSSL_DIR = build/$(OPENSSL_NAME)
RUBY_MAJOR_VERSION = 2.3
RUBY_VERSION = $(RUBY_MAJOR_VERSION).8
RBENV_DIR = $(RBENV_ROOT)/versions/$(RUBY_VERSION)-cryptcheck
RBENV_ROOT ?= ~/.rbenv
export LIBRARY_PATH ?= $(PWD)/lib
export C_INCLUDE_PATH ?= $(PWD)/build/openssl/include
export LD_LIBRARY_PATH ?= $(PWD)/lib

.SECONDARY:
.SUFFIXES:

all: libs rbenv

clean: clean-libs
clean-libs:
	[ -d "build/openssl/" ] \
		&& find "build/openssl/" \( -name "*.o" -o -name "*.so" \) -delete \
		|| true
	rm -f lib/libcrypto.so* lib/libssl.so* "build/openssl//Makefile"
mr-proper:
	rm -rf lib/libcrypto.so* lib/libssl.so* lib/openssl.so build

build/:
	mkdir "$@"

build/chacha-poly.patch: | build/
	wget https://github.com/cloudflare/sslconfig/raw/master/patches/openssl__chacha20_poly1305_draft_and_rfc_ossl102j.patch -O "$@"

build/$(OPENSSL_NAME).tar.gz: | build/
	wget "https://www.openssl.org/source/$(OPENSSL_NAME).tar.gz" -O "$@"

build/openssl/: | $(OPENSSL_DIR)/
	ln -s "$(OPENSSL_NAME)" "build/openssl"

$(OPENSSL_DIR)/: build/$(OPENSSL_NAME).tar.gz build/chacha-poly.patch
	tar -C build -xf "build/$(OPENSSL_NAME).tar.gz"
	patch -d "$(OPENSSL_DIR)" -p1 < build/chacha-poly.patch
	for p in patches/openssl/*.patch; do patch -d "$@" -p1 < "$$p"; done

build/openssl/Makefile: | build/openssl/
	cd build/openssl/ && ./config enable-ssl2 enable-ssl3 enable-ssl3-method enable-md2 enable-rc5 enable-weak-ssl-ciphers enable-shared

build/openssl/libssl.so \
build/openssl/libcrypto.so: build/openssl/Makefile
	$(MAKE) -C build/openssl/

LIBS = lib/libssl.so lib/libcrypto.so lib/libssl.so.$(OPENSSL_LIB_VERSION) lib/libcrypto.so.$(OPENSSL_LIB_VERSION)
lib/%.so: build/openssl/%.so
	cp "$<" "$@"
lib/%.so.$(OPENSSL_LIB_VERSION): lib/%.so
	ln -fs "$(notdir $(subst .$(OPENSSL_LIB_VERSION),,$@))" "$@"
libs: $(LIBS)

$(RBENV_ROOT)/:
	git clone https://github.com/rbenv/rbenv/ $@ -b v1.1.1 --depth 1

$(RBENV_ROOT)/plugins/ruby-build/: | $(RBENV_ROOT)/
	git clone https://github.com/rbenv/ruby-build/ $@ -b v20171215 --depth 1

$(RBENV_ROOT)/plugins/ruby-build/share/ruby-build/$(RUBY_VERSION): | $(RBENV_ROOT)/plugins/ruby-build/

build/$(RUBY_VERSION)-cryptcheck: $(RBENV_ROOT)/plugins/ruby-build/share/ruby-build/$(RUBY_VERSION)
	cp $< $@

rbenv: build/$(RUBY_VERSION)-cryptcheck $(LIBS) | $(OPENSSL_DIR)/
	cat patches/ruby/*.patch | \
	RUBY_BUILD_CACHE_PATH=$(PWD)/build \
	RUBY_BUILD_DEFINITIONS=$(PWD)/build \
	MAKE_OPTS="-j $(shell nproc)" rbenv install -fp $(RUBY_VERSION)-cryptcheck
	# rbenv sequester $(RUBY_VERSION)-cryptcheck
	rbenv local $(RUBY_VERSION)-cryptcheck
	gem install bundler
	bundle install

spec/faketime/libfaketime.so: spec/faketime/faketime.c spec/faketime/faketime.h
	$(CC) $^ -o $@ -shared -fPIC -ldl -std=c99 -Werror -Wall
lib/libfaketime.so: spec/faketime/libfaketime.so
	ln -fs ../$< $@
faketime: lib/libfaketime.so

test-material:
	bin/generate-test-material.rb

test: spec/faketime/libfaketime.so
	bin/rspec

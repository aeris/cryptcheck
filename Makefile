PWD = $(shell pwd)
export CPATH = $(PWD)/openssl/include
export LIBRARY_PATH = $(PWD)/openssl
OPENSSL_LIB_VERSION = 1.0.0
OPENSSL_VERSION = 1.0.2g
#OPENSSL_LIB_VERSION = 1.1
#OPENSSL_VERSION = 1.1.0-pre5
OPENSSL_NAME = openssl-$(OPENSSL_VERSION)
OPENSSL_DIR = build/$(OPENSSL_NAME)
#OPENSSL_DIR = openssl
RUBY_MAJOR_VERSION = 2.3
RUBY_VERSION = $(RUBY_MAJOR_VERSION).1
RUBY_NAME = ruby-$(RUBY_VERSION)
RUBY_DIR = build/$(RUBY_NAME)
RUBY_OPENSSL_EXT_DIR = $(RUBY_DIR)/ext/openssl
export LIBRARY_PATH = $(PWD)/lib
export C_INCLUDE_PATH = $(PWD)/$(OPENSSL_DIR)/include

.SECONDARY:

all: libs ext

clean: clean-libs clean-ext
clean-libs:
	[ -d $(OPENSSL_DIR) ] \
		&& find $(OPENSSL_DIR) \( -name "*.o" -o -name "*.so" \) -delete \
		|| true
	rm -f lib/libcrypto.so* lib/libssl.so* $(OPENSSL_DIR)/Makefile
clean-ext:
	[ -d $(RUBY_OPENSSL_EXT_DIR) ] \
		&& find $(RUBY_OPENSSL_EXT_DIR) \( -name "*.o" -o -name "*.so" \) -delete \
		|| true
	rm -f lib/openssl.so
mr-proper:
	rm -rf lib/libcrypto.so* lib/libssl.so* lib/openssl.so build

build/:
	mkdir $@

build/chacha-poly.patch: | build/
	wget https://github.com/cloudflare/sslconfig/raw/master/patches/openssl__chacha20_poly1305_draft_and_rfc_ossl102g.patch -O $@

build/$(OPENSSL_NAME).tar.gz: | build/
	wget https://www.openssl.org/source/$(OPENSSL_NAME).tar.gz -O $@

$(OPENSSL_DIR)/: build/$(OPENSSL_NAME).tar.gz build/chacha-poly.patch
	tar -C build -xf build/$(OPENSSL_NAME).tar.gz
	patch -d $(OPENSSL_DIR) -p1 < build/chacha-poly.patch

$(OPENSSL_DIR)/Makefile: | $(OPENSSL_DIR)/
	cd $(OPENSSL_DIR) && ./Configure enable-ssl2 enable-ssl3 enable-weak-ssl-ciphers enable-shared linux-x86_64

$(OPENSSL_DIR)/libssl.so \
$(OPENSSL_DIR)/libcrypto.so: $(OPENSSL_DIR)/Makefile
	$(MAKE) -C $(OPENSSL_DIR)

lib/%.so: $(OPENSSL_DIR)/%.so
	cp $< $@
lib/%.so.$(OPENSSL_LIB_VERSION): lib/%.so
	ln -fs $(notdir $(subst .$(OPENSSL_LIB_VERSION),,$@)) $@
libs: lib/libssl.so lib/libcrypto.so lib/libssl.so.$(OPENSSL_LIB_VERSION) lib/libcrypto.so.$(OPENSSL_LIB_VERSION)

build/$(RUBY_NAME).tar.gz: | build/
	wget http://cache.ruby-lang.org/pub/ruby/$(RUBY_MAJOR_VERSION)/$(RUBY_NAME).tar.gz -O $@

$(RUBY_DIR)/: build/$(RUBY_NAME).tar.gz
	tar -C build -xf $<

$(RUBY_OPENSSL_EXT_DIR)/Makefile: libs | $(RUBY_DIR)/
	patch -d $(RUBY_DIR)/ -p1 < tmp_key.patch
	patch -d $(RUBY_DIR)/ -p1 < set_ecdh_curves.patch
	cd $(RUBY_OPENSSL_EXT_DIR) && ruby extconf.rb

$(RUBY_OPENSSL_EXT_DIR)/openssl.so: libs $(RUBY_OPENSSL_EXT_DIR)/Makefile
	top_srcdir=../.. $(MAKE) -C $(RUBY_OPENSSL_EXT_DIR)

lib/openssl.so: $(RUBY_OPENSSL_EXT_DIR)/openssl.so
	cp $< $@

ext: lib/openssl.so

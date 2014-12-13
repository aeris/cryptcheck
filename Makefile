PWD = $(shell pwd)
export CPATH = $(PWD)/openssl/include
export LIBRARY_PATH = $(PWD)/openssl
OPENSSL_VERSION = OpenSSL_1_0_1j
RUBY_VERSION = 2.1.5
RUBY_OPENSSL_EXT_DIR = ruby-$(RUBY_VERSION)/ext/openssl

all: lib/libssl.so.1.0.0 lib/libcrypto.so.1.0.0 lib/openssl.so

clean:
	rm -rf ruby-$(RUBY_VERSION) openssl

openssl:
	git clone https://github.com/openssl/openssl -b $(OPENSSL_VERSION)

openssl/Makefile: openssl
	cd openssl; ./config shared

openssl/libssl.so: openssl/Makefile
	cd openssl; $(MAKE) depend all

lib/%.so.1.0.0: openssl/%.so
	cp $^ $@

ruby-$(RUBY_VERSION):
	wget http://cache.ruby-lang.org/pub/ruby/2.1/ruby-$(RUBY_VERSION).tar.gz
	tar xf ruby-$(RUBY_VERSION).tar.gz
	rm -f ruby-$(RUBY_VERSION).tar.gz

$(RUBY_OPENSSL_EXT_DIR)/Makefile: ruby-$(RUBY_VERSION)
	cd $(RUBY_OPENSSL_EXT_DIR); ruby extconf.rb
	patch $@ patch

$(RUBY_OPENSSL_EXT_DIR)/openssl.so: $(RUBY_OPENSSL_EXT_DIR)/Makefile
	cd $(RUBY_OPENSSL_EXT_DIR); $(MAKE); $(MAKE) install

lib/openssl.so: $(RUBY_OPENSSL_EXT_DIR)/openssl.so
	cp $< $@

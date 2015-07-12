PWD = $(shell pwd)
export CPATH = $(PWD)/openssl/include
export LIBRARY_PATH = $(PWD)/openssl
OPENSSL_VERSION = 1.0.1m
OPENSSL_DIR = openssl-$(OPENSSL_VERSION)
RUBY_MAJOR_VERSION = 2.2
RUBY_VERSION = $(RUBY_MAJOR_VERSION).2
RUBY_DIR = ruby-$(RUBY_VERSION)
RUBY_OPENSSL_EXT_DIR = $(RUBY_DIR)/ext/openssl
export LIBRARY_PATH = $(PWD)/lib
export C_INCLUDE_PATH = $(PWD)/$(OPENSSL_DIR)/include

.SECONDARY:

all: libs ext

clean:
	rm -rf $(RUBY_DIR) $(OPENSSL_DIR)

mr-proper: clean
	rm -rf lib/libcrypto.so* lib/libssl.so* lib/openssl.so

$(OPENSSL_DIR)/:
	wget https://www.openssl.org/source/$(OPENSSL_DIR).tar.gz
	tar xf $(OPENSSL_DIR).tar.gz
	rm -rf $(OPENSSL_DIR).tar.gz

$(OPENSSL_DIR)/Makefile: $(OPENSSL_DIR)/
	cd $(OPENSSL_DIR); ./config shared

$(OPENSSL_DIR)/libssl.so.1.0.0 $(OPENSSL_DIR)/libcrypto.so.1.0.0: $(OPENSSL_DIR)/Makefile
	$(MAKE) -C $(OPENSSL_DIR) depend build_libs

lib/%.so.1.0.0: $(OPENSSL_DIR)/%.so.1.0.0
	cp $< $@

lib/%.so: lib/%.so.1.0.0
	ln -s $(notdir $<) $@

libs: lib/libssl.so lib/libcrypto.so

$(RUBY_DIR):
	wget http://cache.ruby-lang.org/pub/ruby/$(RUBY_MAJOR_VERSION)/$(RUBY_DIR).tar.gz
	tar xf $(RUBY_DIR).tar.gz
	rm -f $(RUBY_DIR).tar.gz

$(RUBY_OPENSSL_EXT_DIR)/Makefile: libs $(RUBY_DIR)
	cd $(RUBY_OPENSSL_EXT_DIR); ruby extconf.rb
	patch $@ patch

$(RUBY_OPENSSL_EXT_DIR)/openssl.so: libs $(RUBY_OPENSSL_EXT_DIR)/Makefile
	$(MAKE) -C $(RUBY_OPENSSL_EXT_DIR)

lib/openssl.so: $(RUBY_OPENSSL_EXT_DIR)/openssl.so
	cp $< $@

ext: lib/openssl.so
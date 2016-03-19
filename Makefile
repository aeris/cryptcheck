PWD = $(shell pwd)
export CPATH = $(PWD)/openssl/include
export LIBRARY_PATH = $(PWD)/openssl
OPENSSL_VERSION = 1.0.2g
OPENSSL_NAME = openssl-$(OPENSSL_VERSION)
OPENSSL_DIR = build/$(OPENSSL_NAME)
#OPENSSL_DIR = openssl
RUBY_MAJOR_VERSION = 2.3
RUBY_VERSION = $(RUBY_MAJOR_VERSION).0
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

$(OPENSSL_DIR)/: | build/
	cd build && \
		wget https://www.openssl.org/source/$(OPENSSL_NAME).tar.gz && \
		tar xf $(OPENSSL_NAME).tar.gz && \
		rm -rf $(OPENSSL_NAME).tar.gz

$(OPENSSL_DIR)/Makefile: | $(OPENSSL_DIR)/
	cd $(OPENSSL_DIR); ./Configure enable-ssl3 enable-ssl2 enable-shared linux-x86_64

$(OPENSSL_DIR)/libssl.so \
$(OPENSSL_DIR)/libcrypto.so: $(OPENSSL_DIR)/Makefile
	$(MAKE) -C $(OPENSSL_DIR) depend build_libs

lib/%.so: $(OPENSSL_DIR)/%.so
	cp $< $@
lib/%.so.1.0.0:
	ln -fs $(notdir $(subst .1.0.0,, $@)) $@
libs: lib/libssl.so lib/libcrypto.so lib/libssl.so.1.0.0 lib/libcrypto.so.1.0.0

$(RUBY_DIR)/: | build/
	cd build && \
		wget http://cache.ruby-lang.org/pub/ruby/$(RUBY_MAJOR_VERSION)/$(RUBY_NAME).tar.gz && \
		tar xf $(RUBY_NAME).tar.gz && \
		rm -f $(RUBY_NAME).tar.gz

$(RUBY_OPENSSL_EXT_DIR)/Makefile: libs | $(RUBY_DIR)/
	cd $(RUBY_OPENSSL_EXT_DIR); ruby extconf.rb
	patch -p0 -d $(RUBY_OPENSSL_EXT_DIR) < patch

$(RUBY_OPENSSL_EXT_DIR)/openssl.so: libs $(RUBY_OPENSSL_EXT_DIR)/Makefile
	$(MAKE) -C $(RUBY_OPENSSL_EXT_DIR)

lib/openssl.so: $(RUBY_OPENSSL_EXT_DIR)/openssl.so
	cp $< $@

ext: lib/openssl.so

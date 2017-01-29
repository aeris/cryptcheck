PWD = $(shell pwd)
OPENSSL_LIB_VERSION = 1.0.0
OPENSSL_VERSION = 1.0.2g
OPENSSL_NAME = openssl-$(OPENSSL_VERSION)
OPENSSL_DIR = build/$(OPENSSL_NAME)
RUBY_MAJOR_VERSION = 2.3
RUBY_VERSION = $(RUBY_MAJOR_VERSION).3
RUBY_NAME = ruby-$(RUBY_VERSION)
RUBY_DIR = build/$(RUBY_NAME)
RUBY_OPENSSL_EXT_DIR = $(RUBY_DIR)/ext/openssl
RUBY_LIB_DIR = $(RBENV_ROOT)/versions/$(RUBY_VERSION)-cryptcheck/lib/ruby/$(RUBY_MAJOR_VERSION).0
RBENV_ROOT ?= ~/.rbenv
export LIBRARY_PATH = $(PWD)/lib
export C_INCLUDE_PATH = $(PWD)/$(OPENSSL_DIR)/include
export LD_LIBRARY_PATH = $(PWD)/lib

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
	#cd $(OPENSSL_DIR) && ./Configure enable-ssl2 enable-ssl3 enable-weak-ssl-ciphers enable-zlib enable-rc5 enable-rc2 enable-gost enable-md2 enable-mdc2 enable-shared linux-x86_64
	#cd $(OPENSSL_DIR) && ./config enable-ssl2 enable-ssl3 enable-md2 enable-rc5 enable-weak-ssl-ciphers shared
	cd $(OPENSSL_DIR) && ./config enable-ssl2 enable-ssl3 enable-ssl3-method enable-md2 enable-rc5 enable-weak-ssl-ciphers enable-shared

$(OPENSSL_DIR)/libssl.so \
$(OPENSSL_DIR)/libcrypto.so: $(OPENSSL_DIR)/Makefile
	$(MAKE) -C $(OPENSSL_DIR)

LIBS = lib/libssl.so lib/libcrypto.so lib/libssl.so.$(OPENSSL_LIB_VERSION) lib/libcrypto.so.$(OPENSSL_LIB_VERSION)
lib/%.so: $(OPENSSL_DIR)/%.so
	cp $< $@
lib/%.so.$(OPENSSL_LIB_VERSION): lib/%.so
	ln -fs $(notdir $(subst .$(OPENSSL_LIB_VERSION),,$@)) $@
libs: $(LIBS)

build/$(RUBY_VERSION)-cryptcheck: $(RBENV_ROOT)/plugins/ruby-build/share/ruby-build/$(RUBY_VERSION)
	cp $< $@
install-ruby: build/$(RUBY_VERSION)-cryptcheck $(LIBS) | $(OPENSSL_DIR)/
	cat tmp_key.patch set_ecdh_curves.patch fallback_scsv.patch multiple_certs.patch | \
	RUBY_BUILD_CACHE_PATH=$(PWD)/build \
	RUBY_BUILD_DEFINITIONS=$(PWD)/build \
	rbenv install -fp $(RUBY_VERSION)-cryptcheck
	rbenv sequester $(RUBY_VERSION)-cryptcheck
	rbenv local $(RUBY_VERSION)-cryptcheck
	gem install bundler
	bundle
$(RUBY_LIB_DIR)/openssl/ssl.rb: $(RUBY_OPENSSL_EXT_DIR)/lib/openssl/ssl.rb
	cp $< $@
$(RUBY_LIB_DIR)/x86_64-linux/openssl.so: $(RUBY_OPENSSL_EXT_DIR)/openssl.so
	cp $< $@
sync-ruby: $(RUBY_LIB_DIR)/openssl/ssl.rb $(RUBY_LIB_DIR)/x86_64-linux/openssl.so

build/$(RUBY_NAME).tar.xz: | build/
	wget http://cache.ruby-lang.org/pub/ruby/$(RUBY_MAJOR_VERSION)/$(RUBY_NAME).tar.xz -O $@

$(RUBY_DIR)/: build/$(RUBY_NAME).tar.xz
	tar -C build -xf $<

$(RUBY_OPENSSL_EXT_DIR)/Makefile: libs | $(RUBY_DIR)/
	patch -d $(RUBY_DIR)/ -p1 < tmp_key.patch
	patch -d $(RUBY_DIR)/ -p1 < set_ecdh_curves.patch
	patch -d $(RUBY_DIR)/ -p1 < fallback_scsv.patch
	patch -d $(RUBY_DIR)/ -p1 < multiple_certs.patch
	cd $(RUBY_OPENSSL_EXT_DIR) && ruby extconf.rb

$(RUBY_OPENSSL_EXT_DIR)/openssl.so: $(LIBS) #$(RUBY_OPENSSL_EXT_DIR)/Makefile
	top_srcdir=../.. $(MAKE) -C $(RUBY_OPENSSL_EXT_DIR)

lib/openssl.so: $(RUBY_OPENSSL_EXT_DIR)/openssl.so
	cp $< $@

ext: lib/openssl.so

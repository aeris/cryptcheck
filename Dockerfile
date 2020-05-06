FROM alpine:3.11 AS builder
MAINTAINER aeris <aeris@imirhil.fr>

ARG OPENSSL_VERSION=1.0.2j
ARG OPENSSL_BINDING=1.0
ARG OPENSSL_LIB_VERSION=1.0.0
ARG RUBY_VERSION=2.3.8-cryptcheck

RUN apk add --update make gcc \
	linux-headers readline-dev libxml2-dev yaml-dev zlib-dev libffi-dev gdbm-dev ncurses-dev \
	ca-certificates wget patch perl musl-dev bash coreutils git

ENV PATH /usr/local/rbenv/shims:/usr/local/rbenv/bin:$PATH
ENV RBENV_ROOT /usr/local/rbenv
ENV RUBY_CONFIGURE_OPTS --disable-install-doc
ENV LD_LIBRARY_PATH /cryptcheck/lib

WORKDIR /cryptcheck/
COPY . /cryptcheck/

RUN make openssl-$OPENSSL_BINDING rbenv ruby-$OPENSSL_BINDING && \
	cp build/openssl-$OPENSSL_VERSION/libssl.so \
		build/openssl-$OPENSSL_VERSION/libssl.so.$OPENSSL_LIB_VERSION \
		build/openssl-$OPENSSL_VERSION/libcrypto.so \
		build/openssl-$OPENSSL_VERSION/libcrypto.so.$OPENSSL_LIB_VERSION \
		lib && \
	make clean
RUN echo "gem: --no-test --no-document" > /root/.gemrc && \
	rbenv local $RUBY_VERSION && \
	gem install bundler && \
	rm -f Gemfile.lock && bundle update && \
	bundle config set deployment true && \
	bundle config set without 'development test' && \
	bundle install

FROM alpine:3.11 AS engine
MAINTAINER aeris <aeris@imirhil.fr>

WORKDIR /cryptcheck/
RUN apk add --update tini bash ca-certificates libxml2 yaml zlib libffi gdbm ncurses
ENV PATH /usr/local/rbenv/shims:/usr/local/rbenv/bin:$PATH
ENV LD_LIBRARY_PATH /cryptcheck/lib
ENV RBENV_ROOT /usr/local/rbenv

ENTRYPOINT ["/sbin/tini", "--", "/cryptcheck/bin/cryptcheck"]

COPY --from=builder /root/.gemrc /root/.gemrc
COPY --from=builder /usr/local/rbenv/ /usr/local/rbenv/
COPY --from=builder /cryptcheck/ /cryptcheck/

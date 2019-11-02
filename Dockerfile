FROM alpine:3.10 AS builder
MAINTAINER aeris <aeris@imirhil.fr>

RUN apk add --update make gcc \
	linux-headers readline-dev libxml2-dev yaml-dev zlib-dev libffi-dev gdbm-dev ncurses-dev \
	ca-certificates wget patch perl musl-dev bash coreutils git

ENV PATH /usr/local/rbenv/shims:/usr/local/rbenv/bin:$PATH
ENV RBENV_ROOT /usr/local/rbenv
ENV RUBY_CONFIGURE_OPTS --disable-install-doc

ENV C_INCLUDE_PATH /cryptcheck/build/openssl/include
ENV CPLUS_INCLUDE_PATH /cryptcheck/build/openssl/include
ENV LIBRARY_PATH /cryptcheck/lib
ENV LD_LIBRARY_PATH /cryptcheck/lib

RUN git clone https://github.com/rbenv/rbenv "$RBENV_ROOT" -b v1.1.2 --depth 1
RUN git clone https://github.com/sstephenson/ruby-build "$RBENV_ROOT/plugins/ruby-build"

WORKDIR /cryptcheck/
COPY . /cryptcheck/

RUN make libs
RUN make rbenv
RUN echo "gem: --no-test --no-document" > /etc/gemrc && \
	gem install bundler && \
	bundle install --deployment --without development test

FROM alpine:3.10 AS engine
MAINTAINER aeris <aeris@imirhil.fr>

WORKDIR /cryptcheck/
RUN apk add --update tini bash ca-certificates libxml2 yaml zlib libffi gdbm ncurses
ENV PATH /usr/local/rbenv/shims:/usr/local/rbenv/bin:$PATH
ENV LD_LIBRARY_PATH /cryptcheck/lib

ENTRYPOINT ["/sbin/tini", "--", "/cryptcheck/bin/cryptcheck"]

COPY --from=builder /etc/gemrc /etc/gemrc
COPY --from=builder /usr/local/rbenv/ /usr/local/rbenv/
COPY --from=builder /cryptcheck/ /cryptcheck/


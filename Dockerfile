FROM alpine:3.7 AS builder
MAINTAINER aeris <aeris@imirhil.fr>

RUN apk add --update make gcc \
	linux-headers readline-dev libxml2-dev yaml-dev zlib-dev libffi-dev gdbm-dev ncurses-dev \
	ca-certificates wget patch perl musl-dev bash coreutils git

ENV LD_LIBRARY_PATH /usr/local/ssl/lib

WORKDIR /cryptcheck/
COPY . /cryptcheck/

RUN make install-openssl
RUN PATH=/usr/local/ssl/bin:$PATH \
	LIBRARY_PATH=$LD_LIBRARY_PATH \
	C_INCLUDE_PATH=/usr/local/ssl/include \
	ac_cv_func_isnan=yes ac_cv_func_isinf=yes \
	make install-ruby && \
	make mr-proper
RUN echo "gem: --no-test --no-document" > /etc/gemrc && \
	gem install bundler && \
	bundle install --deployment --without development test

FROM alpine:3.7 AS engine
MAINTAINER aeris <aeris@imirhil.fr>

WORKDIR /cryptcheck/
RUN apk add --update bash ca-certificates libxml2 yaml zlib libffi gdbm ncurses
ENV LD_LIBRARY_PATH /usr/local/ssl/lib/

COPY --from=builder /etc/gemrc /etc/gemrc
COPY --from=builder /usr/local/ssl/ /usr/local/ssl/
COPY --from=builder /usr/local/include/ruby-2.3.0/ /usr/local/include/ruby-2.3.0/
COPY --from=builder /usr/local/bin/bundle \
					/usr/local/bin/bundler\
					/usr/local/bin/gem \
					/usr/local/bin/rake \
					/usr/local/bin/ruby \
					/usr/local/bin/
COPY --from=builder /usr/local/lib/libruby* /usr/local/lib/
COPY --from=builder /usr/local/lib/ruby/ /usr/local/lib/ruby/
COPY --from=builder /cryptcheck/ /cryptcheck/

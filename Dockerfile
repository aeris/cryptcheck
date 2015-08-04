#
# Dockerfile
#

FROM debian:jessie
MAINTAINER Yann Verry <docker@verry.org>

# Add ruby openssl patch to support DH (from aeris)
ADD /ruby-openssl-dh.patch /tmp/ruby-openssl-dh.patch

# install build env
RUN apt-get update && \
    apt-get dist-upgrade -y && \
    apt-get -y install wget git build-essential zlib1g-dev zlib1g zlibc locales ca-certificates
   
# OpenSSL
RUN cd /usr/src && \
    wget https://www.openssl.org/source/openssl-1.0.2d.tar.gz && \
    tar xf openssl-1.0.2d.tar.gz && \
    cd openssl-1.0.2d && \
    ./config shared && \
    make && \
    make install

# add CA and cacert
RUN mkdir /usr/local/share/ca-certificates/cacert.org && \
    wget -P /usr/local/share/ca-certificates/cacert.org http://www.cacert.org/certs/root.crt http://www.cacert.org/certs/class3.crt && \
    /usr/sbin/update-ca-certificates && \
    rmdir /usr/local/ssl/certs && \
    ln -s /etc/ssl/certs /usr/local/ssl/certs

# Ruby
RUN cd /usr/src && \
    wget http://cache.ruby-lang.org/pub/ruby/2.2/ruby-2.2.2.tar.gz && \
    tar xf ruby-2.2.2.tar.gz && \
    cd ruby-2.2.2 && \
    patch -p0 < /tmp/ruby-openssl-dh.patch && \
    ./configure --prefix=/usr --with-openssl=yes --with-openssl-dir=/usr/local/ssl && \
    make && \
    make install
# gem
RUN /usr/bin/gem install logging parallel ruby-progressbar httparty

# Cleanup
RUN rm -rf /usr/src/* && \
    apt-get -y purge build-essential zlib1g-dev && \
    apt-get -y autoremove

# Set the locale
ENV LC_ALL C.UTF-8

# clone sslcheck
RUN cd /opt && \
    git clone https://github.com/yanntech/sslcheck

# expose volume output
VOLUME /opt/sslcheck/output

# CMD
CMD ["/opt/sslcheck/bin/check_https"]

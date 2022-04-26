require_relative 'basic_server'
require 'openssl'

class TlsServer < BasicServer
  def self.key(type, name = nil)
    name = if name
             "#{type}-#{name}"
           else
             type
           end
    OpenSSL::PKey.read File.read "spec/resources/#{name}.pem"
  end

  def self.cert(type, name = nil)
    name = if name
             "#{type}-#{name}"
           else
             type
           end
    OpenSSL::X509::Certificate.new File.read "spec/resources/#{name}.crt"
  end

  def self.chain(chain)
    chain.collect { |f| self.cert f }
  end

  def self.dh(name)
    OpenSSL::PKey::DH.new File.read "spec/resources/dh-#{name}.pem"
  end

  def self.context(materials:, chain: [], methods:, ciphers:,
              dh: [], curves: [], server_preference: true)
    # Can't find a way to support SSLv2 with others
    context         = if methods == :SSLv2
                        OpenSSL::SSL::SSLContext.new :SSLv2
                      else
                        context         = OpenSSL::SSL::SSLContext.new
                        context.options |= OpenSSL::SSL::OP_NO_SSLv2 unless methods.include? :SSLv2
                        context.options |= OpenSSL::SSL::OP_NO_SSLv3 unless methods.include? :SSLv3
                        context.options |= OpenSSL::SSL::OP_NO_TLSv1 unless methods.include? :TLSv1
                        context.options |= OpenSSL::SSL::OP_NO_TLSv1_1 unless methods.include? :TLSv1_1
                        context.options |= OpenSSL::SSL::OP_NO_TLSv1_2 unless methods.include? :TLSv1_2
                        context
                      end
    context.options |= OpenSSL::SSL::OP_CIPHER_SERVER_PREFERENCE if server_preference

    context.certs            = materials.collect { |c| self.cert *c }
    context.keys             = materials.collect { |k| self.key *k }
    context.extra_chain_cert = chain.collect { |c| self.cert c }

    context.ciphers = ciphers.join ':'
    if methods != :SSLv2
      context.tmp_dh_callback = proc { dh } if dh
      context.ecdh_curves     = curves.join ':' if curves
    end

    context
  end

  def context(*args, **kwargs)
    self.class.context *args, **kwargs
  end

  def initialize(*args, **kwargs, &block)
    @tcp_server = TCPServer.new *args
    context     = self.context **kwargs
    tls_server  = OpenSSL::SSL::SSLServer.new @tcp_server, context
    super tls_server, &block
  end

  def on_connect(_)
  end

  def close
    super
    @tcp_server.close
  end
end

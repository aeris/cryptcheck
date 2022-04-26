$:.unshift File.expand_path File.join File.dirname(__FILE__), '../lib'
require 'rubygems'
require 'bundler/setup'
Bundler.require :default, :development

ENV['TCP_TIMEOUT'] = '1'
ENV['TLS_TIMEOUT'] = '1'
require 'cryptcheck'
require 'fake'

require 'simplecov'
SimpleCov.start do
  coverage_dir 'tmp/coverage'
  add_filter 'spec/'
end

require_relative 'lib/tcp_server'
require_relative 'lib/tls_server'

CryptCheck::Logger.level = ENV['LOG'] || :none

module Helpers
  DEFAULT_METHODS  = %i(TLSv1_2)
  DEFAULT_CIPHERS  = %i(ECDHE-ECDSA-AES128-GCM-SHA256)
  DEFAULT_CURVES   = %i(prime256v1)
  DEFAULT_DH       = [:rsa, 4096]
  DEFAULT_MATERIAL = [[:ecdsa, :prime256v1]]
  DEFAULT_CHAIN    = %w(intermediate ca)
  DEFAULT_HOST     = 'localhost'
  DEFAULT_IPv4     = '127.0.0.1'
  DEFAULT_IPv6     = '::1'
  DEFAULT_PORT     = 15000

  default_parameters       = {
    methods:           %i(TLSv1_2),
    chain:             %w(intermediate ca),
    curves:            %i(prime256v1),
    server_preference: true
  }.freeze
  default_ecdsa_parameters = default_parameters.merge({
                                                        materials: [[:ecdsa, :prime256v1]],
                                                        ciphers:   %i(ECDHE-ECDSA-AES128-SHA),
                                                        curves:    %i(prime256v1)
                                                      }).freeze
  default_rsa_parameters   = default_parameters.merge({
                                                        materials: [[:rsa, 1024]],
                                                        ciphers:   %i(ECDHE-RSA-AES128-SHA),
                                                        curves:    %i(prime256v1),
                                                        dh:        1024
                                                      }).freeze
  default_mixed_parameters = default_parameters.merge({
                                                        materials: [[:ecdsa, :prime256v1], [:rsa, 1024]],
                                                        ciphers:   %i(ECDHE-ECDSA-AES128-SHA ECDHE-RSA-AES128-SHA),
                                                        curves:    %i(prime256v1),
                                                        dh:        1024
                                                      }).freeze
  default_sslv2_parameters = default_parameters.merge({
                                                        methods:   :SSLv2,
                                                        materials: [[:rsa, 1024]],
                                                        ciphers:   %i(RC4-MD5),
                                                        chain:     []
                                                      }).freeze
  DEFAULT_PARAMETERS       = { ecdsa: default_ecdsa_parameters,
                               rsa:   default_rsa_parameters,
                               mixed: default_mixed_parameters,
                               sslv2: default_sslv2_parameters }.freeze

  def cert(*args)
    TlsServer.cert *args
  end

  def chain(chain)
    TlsServer.chain chain
  end

  def serv(host, ips, port, servers, fake_ips: nil)
    fake_ips ||= ips
    Fake.getaddrinfo host, *fake_ips do
      begin
        yield host, port
      ensure
        servers.each { |s| s.close }
      end
    end
  end

  def tls_serv(type = :ecdsa, host: DEFAULT_HOST, ips: [DEFAULT_IPv4, DEFAULT_IPv6],
               fake_ips: nil, port: DEFAULT_PORT, **kwargs, &block)
    params = DEFAULT_PARAMETERS.fetch(type).dup
    params.merge! kwargs
    servers = ips.collect { |ip| TlsServer.new ip, port, **params }
    self.serv host, ips, port, servers, fake_ips: fake_ips, &block
  end

  def plain_serv(host: DEFAULT_HOST, ips: [DEFAULT_IPv4, DEFAULT_IPv6], port: DEFAULT_PORT, &block)
    servers = ips.collect { |ip| TcpServer.new ip, port }
    self.serv host, ips, port, servers, &block
  end

  def starttls_serv(key: DEFAULT_KEY, domain: DEFAULT_HOST, # Key & certificate
                    version: DEFAULT_METHOD, ciphers: DEFAULT_CIPHERS, # TLS version and ciphers
                    dh: DEFAULT_DH_SIZE, ecdh: DEFAULT_ECC_CURVE, # DHE & ECDHE
                    host: DEFAULT_HOST, port: DEFAULT_PORT, # Binding
                    plain_process: nil, process: nil, &block)
    context                      = context(key: key, domain: domain, version: version, ciphers: ciphers, dh: dh, ecdh: ecdh)
    tcp_server                   = TCPServer.new host, port
    tls_server                   = OpenSSL::SSL::SSLServer.new tcp_server, context
    tls_server.start_immediately = false

    internal_process = proc do |socket|
      accept = false
      accept = plain_process.call socket if plain_process
      if accept
        tls_socket = socket.accept
        begin
          process.call tls_socket if process
        ensure
          socket.close
        end
      end
    end

    begin
      serv tls_server, internal_process, &block
    ensure
      tls_server.close
      tcp_server.close
    end
  end

  def server(servers, host, ip, port)
    servers[[host, ip, port]]
  end

  def expect_grade(servers, host, ip, port, family)
    server = server servers, host, ip, port
    expect(server).to be_a CryptCheck::Tls::Server
    expect(server.hostname).to eq host
    expect(server.ip).to eq ip
    expect(server.port).to eq port
    expect(server.family).to eq case family
                                when :ipv4
                                  Socket::AF_INET
                                when :ipv6
                                  Socket::AF_INET6
                                end
  end

  def expect_grade_error(servers, host, ip, port, error)
    server = servers[[host, ip, port]]
    expect(server).to be_a Exception
    expect(server.to_s).to eq error
  end

  def expect_error(error, type, message)
    expect(error).to be_a type
    expect(error.message).to eq message
  end
end

RSpec.configure do |c|
  c.include Helpers
end

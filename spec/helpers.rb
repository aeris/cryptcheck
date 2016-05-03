$:.unshift File.expand_path File.join File.dirname(__FILE__), '../lib'
require 'rubygems'
require 'bundler/setup'
require 'cryptcheck'

CryptCheck::Logger.level = ENV['LOG'] || :none

module Helpers
	OpenSSL::PKey::EC.send :alias_method, :private?, :private_key?

	def key(name)
		open(File.join(File.dirname(__FILE__), 'resources', "#{name}.pem"), 'r') { |f| OpenSSL::PKey.read f }
	end

	def dh(name)
		open(File.join(File.dirname(__FILE__), 'resources', "dh-#{name}.pem"), 'r') { |f| OpenSSL::PKey::DH.new f }
	end

	def certificate(key, domain)
		cert            = OpenSSL::X509::Certificate.new
		cert.version    = 2
		cert.serial     = rand 2**(20*8-1) .. 2**(20*8)
		cert.not_before = Time.now
		cert.not_after  = cert.not_before + 60*60

		cert.public_key = case key
							  when OpenSSL::PKey::EC
								  curve             = key.group.curve_name
								  public            = OpenSSL::PKey::EC.new curve
								  public.public_key = key.public_key
								  public
							  else
								  key.public_key
						  end

		name         = OpenSSL::X509::Name.parse "CN=#{domain}"
		cert.subject = name
		cert.issuer  = name

		extension_factory                     = OpenSSL::X509::ExtensionFactory.new nil, cert
		extension_factory.subject_certificate = cert
		extension_factory.issuer_certificate  = cert

		cert.add_extension extension_factory.create_extension 'basicConstraints', 'CA:TRUE', true
		cert.add_extension extension_factory.create_extension 'keyUsage', 'keyEncipherment, dataEncipherment, digitalSignature,nonRepudiation,keyCertSign'
		cert.add_extension extension_factory.create_extension 'extendedKeyUsage', 'serverAuth, clientAuth'
		cert.add_extension extension_factory.create_extension 'subjectKeyIdentifier', 'hash'
		cert.add_extension extension_factory.create_extension 'authorityKeyIdentifier', 'keyid:always'
		cert.add_extension extension_factory.create_extension 'subjectAltName', "DNS:#{domain}"

		cert.sign key, OpenSSL::Digest::SHA512.new
	end

	def server(key: 'rsa-1024', domain: 'localhost', # Key & certificate
			   host: '127.0.0.1', port: 5000, # Binding
			   version: :TLSv1_2, ciphers: 'AES128-SHA', # TLS version and ciphers
			   dh: 1024, ecdh: 'secp256r1') # DHE & ECDHE
		key  = key key
		cert = certificate key, domain

		context         = OpenSSL::SSL::SSLContext.new version
		context.cert    = cert
		context.key     = key
		context.ciphers = ciphers

		if dh
			dh                      = dh dh
			context.tmp_dh_callback = proc { dh }
		end
		if ecdh
			ecdh                      = key ecdh
			context.tmp_ecdh_callback = proc { ecdh }
		end

		IO.pipe do |stop_pipe_r, stop_pipe_w|
			threads = []

			mutex = Mutex.new
			started = ConditionVariable.new

			threads << Thread.start do
				tcp_server = TCPServer.new host, port
				ssl_server = OpenSSL::SSL::SSLServer.new tcp_server, context

				mutex.synchronize { started.signal }

				loop do
					readable, = IO.select [ssl_server, stop_pipe_r]
					break if readable.include? stop_pipe_r
					begin
						ssl_server.accept
					rescue
					end
				end
				ssl_server.close
				tcp_server.close
			end

			mutex.synchronize { started.wait mutex }
			begin
				yield
			ensure
				stop_pipe_w.close
				threads.each &:join
			end
		end
	end

	def plain_server(host: '127.0.0.1', port: 5000)
		IO.pipe do |stop_pipe_r, stop_pipe_w|
			threads = []

			mutex = Mutex.new
			started = ConditionVariable.new

			threads << Thread.start do
				tcp_server = TCPServer.new host, port
				mutex.synchronize { started.signal }

				loop do
					readable, = IO.select [tcp_server, stop_pipe_r]
					break if readable.include? stop_pipe_r
					begin
						tcp_server.accept
					rescue
					end
				end
				tcp_server.close
			end

			mutex.synchronize { started.wait mutex }
			begin
				yield
			ensure
				stop_pipe_w.close
				threads.each &:join
			end
		end
	end

	def expect_grade(grades, host, ip, port, family)
		server = grades[[host, ip, port]].server
		expect(server).to be_a CryptCheck::Tls::Server
		expect(server.hostname).to eq host
		expect(server.ip).to eq ip
		expect(server.port).to eq port
		expect(server.family).to eq case family
										when :ipv4 then Socket::AF_INET
										when :ipv6 then Socket::AF_INET6
									end
	end

	def expect_grade_error(grades, host, ip, port, error)
		server = grades[[host, ip, port]]
		expect(server).to be_a CryptCheck::AnalysisFailure
		expect(server.to_s).to eq error
	end
end

RSpec.configure do |c|
	c.include Helpers
end

$:.unshift File.expand_path File.join File.dirname(__FILE__), '../lib'
require 'rubygems'
require 'bundler/setup'
require 'cryptcheck'
Dir['./spec/**/support/**/*.rb'].sort.each { |f| require f }

CryptCheck::Logger.level = ENV['LOG'] || :none

module Helpers
	DEFAULT_KEY = 'rsa-1024'
	DEFAULT_METHOD = :TLSv1_2
	DEFAULT_CIPHERS = %w(AES128-SHA)
	DEFAULT_ECC_CURVE = 'secp256k1'
	DEFAULT_DH_SIZE = 1024

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

	def serv(server, process, &block)
		IO.pipe do |stop_pipe_r, stop_pipe_w|
			threads = []

			mutex   = Mutex.new
			started = ConditionVariable.new

			threads << Thread.start do
				mutex.synchronize { started.signal }

				loop do
					readable, = IO.select [server, stop_pipe_r]
					break if readable.include? stop_pipe_r

					begin
						socket = server.accept
						begin
							process.call socket if process
						ensure
							socket.close
						end
					rescue
					end
				end
				server.close
			end

			mutex.synchronize { started.wait mutex }
			begin
				block.call if block
			ensure
				stop_pipe_w.close
				threads.each &:join
			end
		end
	end

	def context(key: DEFAULT_KEY, domain: 'localhost', # Key & certificate
				version: DEFAULT_METHOD, ciphers: DEFAULT_CIPHERS, # TLS version and ciphers
				dh: DEFAULT_DH_SIZE, ecdh: DEFAULT_ECC_CURVE) # DHE & ECDHE
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
		context.ecdh_curves = ecdh if ecdh

		context
	end

	def tls_serv(key: DEFAULT_KEY, domain: 'localhost', # Key & certificate
				 version: DEFAULT_METHOD, ciphers: DEFAULT_CIPHERS, # TLS version and ciphers
				 dh: DEFAULT_DH_SIZE, ecdh: DEFAULT_ECC_CURVE, # DHE & ECDHE
				 host: '127.0.0.1', port: 5000, # Binding
				 process: nil, &block)
		context    = context(key: key, domain: domain, version: version, ciphers: ciphers, dh: dh, ecdh: ecdh)
		tcp_server = TCPServer.new host, port
		tls_server = OpenSSL::SSL::SSLServer.new tcp_server, context
		begin
			serv tls_server, process, &block
		ensure
			tls_server.close
			tcp_server.close
		end
	end

	def plain_serv(host: '127.0.0.1', port: 5000, process: nil, &block)
		tcp_server = TCPServer.new host, port
		begin
			serv tcp_server, process, &block
		ensure
			tcp_server.close
		end
	end

	def starttls_serv(key: DEFAULT_KEY, domain: 'localhost', # Key & certificate
					  version: DEFAULT_METHOD, ciphers: DEFAULT_CIPHERS, # TLS version and ciphers
					  dh: DEFAULT_DH_SIZE, ecdh: DEFAULT_ECC_CURVE, # DHE & ECDHE
					  host: '127.0.0.1', port: 5000, # Binding
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

	def grade(grades, host, ip, port)
		grades[[host, ip, port]]
	end

	def expect_grade(grades, host, ip, port, family)
		grade = grade grades, host, ip, port
		expect(grade).to be_a CryptCheck::Tls::Grade
		server = grade.server
		expect(server).to be_a CryptCheck::Tls::Server
		expect(server.hostname).to eq host
		expect(server.ip).to eq ip
		expect(server.port).to eq port
		expect(server.family).to eq case family
										when :ipv4 then
											Socket::AF_INET
										when :ipv6 then
											Socket::AF_INET6
									end
		[grade, server]
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

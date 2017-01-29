$:.unshift File.expand_path File.join File.dirname(__FILE__), '../lib'
require 'rubygems'
require 'bundler/setup'
Bundler.require :default, :development
require 'cryptcheck'
Dir['./spec/**/support/**/*.rb'].sort.each { |f| require f }

CryptCheck::Logger.level = ENV['LOG'] || :none

module Helpers
	DEFAULT_METHODS  = %i(TLSv1_2)
	DEFAULT_CIPHERS  = %i(ECDHE+AES)
	DEFAULT_CURVES   = %i(prime256v1)
	DEFAULT_DH       = [:rsa, 4096]
	DEFAULT_MATERIAL = [[:ecdsa, :prime256v1]]
	DEFAULT_CHAIN    = %w(intermediate ca)
	DEFAULT_HOST     = 'localhost'
	DEFAULT_PORT     = 5000

	def key(type, name=nil)
		name = if name
				   "#{type}-#{name}"
			   else
				   type
			   end
		OpenSSL::PKey.read File.read "spec/resources/#{name}.pem"
	end

	def cert(type, name=nil)
		name = if name
				   "#{type}-#{name}"
			   else
				   type
			   end
		OpenSSL::X509::Certificate.new File.read "spec/resources/#{name}.crt"
	end

	def dh(name)
		OpenSSL::PKey::DH.new File.read "spec/resources/dh-#{name}.pem"
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

	def context(certs, keys, chain=[],
				methods: DEFAULT_METHODS, ciphers: DEFAULT_CIPHERS,
				dh:, curves: DEFAULT_CURVES, server_preference: true)
		context         = OpenSSL::SSL::SSLContext.new

		context.options |= OpenSSL::SSL::OP_NO_SSLv2 unless methods.include? :SSLv2
		context.options |= OpenSSL::SSL::OP_NO_SSLv3 unless methods.include? :SSLv3
		context.options |= OpenSSL::SSL::OP_NO_TLSv1 unless methods.include? :TLSv1
		context.options |= OpenSSL::SSL::OP_NO_TLSv1_1 unless methods.include? :TLSv1_1
		context.options |= OpenSSL::SSL::OP_NO_TLSv1_2 unless methods.include? :TLSv1_2
		context.options |= OpenSSL::SSL::OP_CIPHER_SERVER_PREFERENCE if server_preference

		context.certs            = certs
		context.keys             = keys
		context.extra_chain_cert = chain if chain

		context.ciphers         = ciphers.join ':'
		context.tmp_dh_callback = proc { dh } if dh
		context.ecdh_curves     = curves.join ':' if curves

		context
	end

	def tls_serv(host: DEFAULT_HOST, port: DEFAULT_PORT,
				 material: DEFAULT_MATERIAL, chain: DEFAULT_CHAIN,
				 methods: DEFAULT_METHODS, ciphers: DEFAULT_CIPHERS,
				 dh: nil, curves: DEFAULT_CURVES, server_preference: true,
				 process: nil, &block)
		keys  = material.collect { |m| key *m }
		certs = material.collect { |m| cert *m }
		chain = chain.collect { |c| cert c }
		dh    = dh dh if dh

		context    = context certs, keys, chain,
							 methods:           methods, ciphers: ciphers,
							 dh:                dh, curves: curves,
							 server_preference: server_preference
		tcp_server = TCPServer.new host, port
		tls_server = OpenSSL::SSL::SSLServer.new tcp_server, context
		begin
			serv tls_server, process, &block
		ensure
			tls_server.close
			tcp_server.close
		end
	end

	def plain_serv(host='127.0.0.1', port=5000, process: nil, &block)
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
										when :ipv4
											Socket::AF_INET
										when :ipv6
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

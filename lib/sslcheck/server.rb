require 'socket'
require 'openssl'
require 'httparty'
require 'parallel'
require 'tcp_timeout'

module SSLCheck
	class NoSslTlsServer
		attr_reader :hostname, :port

		def initialize(hostname, port=443)
			@hostname, @port = hostname, port
		end
	end

	class Server
		TCP_TIMEOUT = 60
		SSL_TIMEOUT = 2*TCP_TIMEOUT
		EXISTING_METHODS = %i(TLSv1_2 TLSv1_1 TLSv1 SSLv3 SSLv2)
		SUPPORTED_METHODS = OpenSSL::SSL::SSLContext::METHODS
		class TLSNotAvailableException < Exception; end
		class CipherNotAvailable < Exception; end
		class Timeout < Exception; end
		class ConnectionError < Exception; end

		attr_reader :hostname, :port, :prefered_ciphers, :cert, :hsts

		def initialize(hostname, port=443, methods: EXISTING_METHODS)
			@log = Logging.logger[hostname]
			@hostname = hostname
			@port = port
			@methods = methods
			@log.error { "Begin analysis" }
			extract_cert
			fetch_prefered_ciphers
			check_supported_cipher
			fetch_hsts
			@log.error { "End analysis" }
		end

		def supported_methods
			worst = EXISTING_METHODS.find { |method| !@prefered_ciphers[method].nil? }
			best = EXISTING_METHODS.reverse.find { |method| !@prefered_ciphers[method].nil? }
			{worst: worst, best: best}
		end

		def key
			key = @cert.public_key
			case key
				when OpenSSL::PKey::RSA then
					[:rsa, key.n.num_bits]
				when OpenSSL::PKey::DSA then
					[:dsa, key.p.num_bits]
				when OpenSSL::PKey::EC then
					[:ecc, key.group.degree]
			end
		end

		def key_size
			type, size = self.key
			if type == :ecc
				size = case size
					when 160 then 1024
					when 224 then 2048
					when 256 then 3072
					when 384 then 7680
					when 521 then 15360
				end
			end
			size
		end

		def cipher_size
			cipher_strengths = supported_ciphers.collect { |c| c[2] }.uniq.sort
			worst, best = cipher_strengths.first, cipher_strengths.last
			{worst: worst, best: best}
		end

		EXISTING_METHODS.each do |method|
			class_eval <<-RUBY_EVAL, __FILE__, __LINE__ + 1
					def #{method.to_s.downcase}?
						!prefered_ciphers[:#{method}].nil?
					end
			RUBY_EVAL
		end

		{
				  md2: %w(md2WithRSAEncryption),
				  md5: %w(md5WithRSAEncryption md5WithRSA),
				  sha1: %w(sha1WithRSAEncryption sha1WithRSA dsaWithSHA1 dsaWithSHA1_2 ecdsa_with_SHA1)
		}.each do |name, signature|
			class_eval <<-RUBY_EVAL, __FILE__, __LINE__ + 1
				def #{name}_sig?
					#{signature}.include? @cert.signature_algorithm
				end
			RUBY_EVAL
		end

		{
				  md5: %w(MD5),
				  sha1: %w(SHA),

				  rc4: %w(RC4),
				  des3: %w(3DES DES-CBC3),
				  des: %w(DES-CBC)
		}.each do |name, ciphers|
			class_eval <<-RUBY_EVAL, __FILE__, __LINE__ + 1
				def #{name}?
					supported_ciphers.any? { |supported| #{ciphers}.any? { |available| /(^|-)#\{available\}(-|$)/ =~ supported[0] } }
				end
			RUBY_EVAL
		end

		def any_des?
			des? or des3?
		end

		def ssl?
			sslv2? or sslv3?
		end

		def tls?
			tlsv1? or tlsv1_1? or tlsv1_2?
		end

		def tls_only?
			tls? and !ssl?
		end

		PFS_CIPHERS = [/^DHE-RSA-/, /^DHE-DSS-/, /^ECDHE-RSA-/, /^ECDHE-ECDSA-/]

		def pfs?
			supported_ciphers.any? { |cipher| PFS_CIPHERS.any? { |pc| pc =~ cipher[0] } }
		end

		def pfs_only?
			supported_ciphers.all? { |cipher| PFS_CIPHERS.any? { |pc| pc =~ cipher[0] } }
		end

		def supported_ciphers
			@supported_ciphers.values.flatten(1).uniq
		end

		def supported_ciphers_by_method
			@supported_ciphers
		end

		def hsts?
			!@hsts.nil?
		end

		def hsts_long?
			hsts? and @hsts >= 6*30*24*60*60
		end

		private
		def connect(family, host, port, &block)
			socket = Socket.new family, Socket::SOCK_STREAM
			sockaddr = Socket.sockaddr_in port, host
			@log.debug { "Connecting to #{host}:#{port}" }
			begin
				status = socket.connect_nonblock sockaddr
				@log.debug { "Connecting to #{host}:#{port} status : #{status}" }
				raise ConnectionError.new status unless status == 0
				@log.debug { "Connected to #{host}:#{port}" }
				block_given? ? block.call(socket) : nil
			rescue IO::WaitReadable
				@log.debug { "Waiting for read to #{host}:#{port}" }
				raise Timeout.new unless IO.select [socket], nil, nil, TCP_TIMEOUT
				retry
			rescue IO::WaitWritable
				@log.debug { "Waiting for write to #{host}:#{port}" }
				raise Timeout.new unless IO.select nil, [socket], nil, TCP_TIMEOUT
				retry
			ensure
				socket.close
			end
		end

		def ssl_connect(socket, context, method, &block)
			ssl_socket = OpenSSL::SSL::SSLSocket.new socket, context
			ssl_socket.hostname = @hostname unless method == :SSLv2
			@log.debug { "SSL connecting to #{@hostname}:#{@port}" }
			begin
				ssl_socket.connect_nonblock
				@log.debug { "SSL connected to #{@hostname}:#{@port}" }
				return block_given? ? block.call(ssl_socket) : nil
			rescue IO::WaitReadable
				@log.debug { "Waiting for SSL read to #{@hostname}:#{@port}" }
				raise Timeout.new unless IO.select [socket], nil, nil, SSL_TIMEOUT
				retry
			rescue IO::WaitWritable
				@log.debug { "Waiting for SSL write to #{@hostname}:#{@port}" }
				raise Timeout.new unless IO.select nil, [socket], nil, SSL_TIMEOUT
				retry
			ensure
				ssl_socket.close
			end
		end

		def ssl_client(method, ciphers = nil, &block)
			ssl_context = OpenSSL::SSL::SSLContext.new method
			ssl_context.ciphers = ciphers if ciphers
			@log.debug { "Try #{method} connection with #{ciphers}" }

			[Socket::AF_INET, Socket::AF_INET6].each do |family|
				@log.debug { "Try connection for family #{family}" }
				addrs = begin
					Socket.getaddrinfo @hostname, nil, family, :STREAM
				rescue SocketError => e
					@log.debug { "Unable to resolv #{@hostname} : #{e}" }
					next
				end

				addrs.each do |addr|
					connect family, addr[3], @port do |socket|
						ssl_connect socket, ssl_context, method do |ssl_socket|
							return block_given? ? block.call(ssl_socket) : nil
						end
					end
				end
			end

			@log.debug { "No SSL available on #{@hostname}" }
			raise CipherNotAvailable.new
		end

		def extract_cert
			@methods.each do |method|
				next unless SUPPORTED_METHODS.include? method
				begin
					@cert = ssl_client(method) { |s| s.peer_cert }
					@log.warn { "Certificate #{@cert.subject}" }
					break
				rescue Exception => e
					@log.info { "Method #{method} not supported : #{e}" }
				end
			end
			raise TLSNotAvailableException.new unless @cert
		end

		def prefered_cipher(method)
			cipher = ssl_client(method, %w(ALL:COMPLEMENTOFALL)) { |s| s.cipher }
			@log.warn { "Prefered cipher for #{method} : #{cipher[0]}" }
			cipher
		rescue Exception => e
			@log.info { "Method #{method} not supported : #{e}" }
			nil
		end

		def fetch_prefered_ciphers
			@prefered_ciphers = {}
			@methods.each do |method|
				next unless SUPPORTED_METHODS.include? method
				@prefered_ciphers[method] = prefered_cipher method
			end
			raise TLSNotAvailableException.new unless @prefered_ciphers.any? { |_, c| !c.nil? }
		end

		def available_ciphers(method)
			OpenSSL::SSL::SSLContext.new(method).ciphers
		end

		def supported_cipher?(method, cipher)
			ssl_client method, [cipher]
			@log.warn { "Verify #{method} / #{cipher[0]} : OK" }
			true
		rescue Exception => e
			@log.info { "Verify #{method} / #{cipher[0]} : NOK (#{e})" }
			false
		end

		def check_supported_cipher
			@supported_ciphers = {}
			@methods.each do |method|
				next unless SUPPORTED_METHODS.include? method and @prefered_ciphers[method]
				@supported_ciphers[method] = available_ciphers(method).select { |cipher| supported_cipher? method, cipher }
			end
		end

		def fetch_hsts
			port = @port == 443 ? '' : ":#{@port}"

			response = nil
			@methods.each do |method|
				begin
					next unless SUPPORTED_METHODS.include? method
					@log.debug { "Check HSTS with #{method}" }
					response = HTTParty.head "https://#{@hostname}#{port}/", {follow_redirects: false, verify: false, ssl_version: method, timeout: SSL_TIMEOUT}
					break
				rescue Exception => e
					@log.debug { "#{method} not supported : #{e}" }
				end
			end

			if response and header = response.headers['strict-transport-security']
				name, value = header.split '='
				if name == 'max-age'
					@hsts = value.to_i
					@log.info { "HSTS : #{@hsts}" }
					return
				end
			end

			@log.info { 'No HSTS' }
			@hsts = nil
		end
	end
end

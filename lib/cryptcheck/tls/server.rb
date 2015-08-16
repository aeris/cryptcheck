require 'socket'
require 'openssl'
require 'httparty'

module CryptCheck
	module Tls
		class TlsNotSupportedServer
			attr_reader :hostname, :port

			def initialize(hostname, port)
				@hostname, @port = hostname, port
			end
		end

		class Server
			TCP_TIMEOUT       = 10
			SSL_TIMEOUT       = 2*TCP_TIMEOUT
			EXISTING_METHODS  = %i(TLSv1_2 TLSv1_1 TLSv1 SSLv3 SSLv2)
			SUPPORTED_METHODS = ::OpenSSL::SSL::SSLContext::METHODS
			class TLSException < ::Exception
			end
			class TLSNotAvailableException < TLSException
			end
			class MethodNotAvailable < TLSException
			end
			class CipherNotAvailable < TLSException
			end
			class Timeout < TLSException
			end
			class TLSTimeout < TLSException
			end
			class ConnectionError < TLSException
			end

			attr_reader :hostname, :port, :prefered_ciphers, :cert, :cert_valid, :cert_trusted

			def initialize(hostname, port)
				@hostname = hostname
				@port     = port
				Logger.info { "#{hostname}:#{port}".colorize :blue }
				extract_cert
				#@prefered_ciphers = @supported_ciphers = Hash[SUPPORTED_METHODS.collect { |m| [m, []]}]
				fetch_prefered_ciphers
				check_supported_cipher
			end

			def supported_methods
				worst = EXISTING_METHODS.find { |method| !@prefered_ciphers[method].nil? }
				best  = EXISTING_METHODS.reverse.find { |method| !@prefered_ciphers[method].nil? }
				{ worst: worst, best: best }
			end

			def key
				key = @cert.public_key
				case key
					when ::OpenSSL::PKey::RSA then
						[:rsa, key.n.num_bits]
					when ::OpenSSL::PKey::DSA then
						[:dsa, key.p.num_bits]
					when ::OpenSSL::PKey::EC then
						[:ecc, key.group.degree]
				end
			end

			def key_size
				type, size = self.key
				if type == :ecc
					size = case size
							   when 160 then
								   1024
							   when 224 then
								   2048
							   when 256 then
								   3072
							   when 384 then
								   7680
							   when 521 then
								   15360
						   end
				end
				size
			end

			def cipher_size
				cipher_strengths = supported_ciphers.collect { |c| c[2] }.uniq.sort
				worst, best      = cipher_strengths.first, cipher_strengths.last
				{ worst: worst, best: best }
			end

			EXISTING_METHODS.each do |method|
				class_eval <<-RUBY_EVAL, __FILE__, __LINE__ + 1
					def #{method.to_s.downcase}?
						!prefered_ciphers[:#{method}].nil?
					end
				RUBY_EVAL
			end

			{
					md2:  %w(md2WithRSAEncryption),
					md5:  %w(md5WithRSAEncryption md5WithRSA),
					sha1: %w(sha1WithRSAEncryption sha1WithRSA dsaWithSHA1 dsaWithSHA1_2 ecdsa_with_SHA1)
			}.each do |name, signature|
				class_eval <<-RUBY_EVAL, __FILE__, __LINE__ + 1
					def #{name}_sig?
						#{signature}.include? @cert.signature_algorithm
					end
				RUBY_EVAL
			end

			Tls::TYPES.each do |type, _|
				class_eval <<-RUBY_EVAL, __FILE__, __LINE__ + 1
					def #{type}?
						supported_ciphers.any? { |s| Tls.#{type}? s.first  }
					end
				RUBY_EVAL
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

			def pfs?
				supported_ciphers.any? { |c| Tls.pfs? c.first }
			end

			def pfs_only?
				supported_ciphers.all? { |c| Tls.pfs? c.first }
			end

			def supported_ciphers
				@supported_ciphers.values.flatten(1).uniq
			end

			def supported_ciphers_by_method
				@supported_ciphers
			end

			private
			def connect(family, host, port, &block)
				socket   = ::Socket.new family, sock_type
				sockaddr = ::Socket.sockaddr_in port, host
				Logger.trace { "Connecting to #{host}:#{port}" }
				begin
					status = socket.connect_nonblock sockaddr
					Logger.trace { "Connecting to #{host}:#{port} status : #{status}" }
					raise ConnectionError, status unless status == 0
					Logger.trace { "Connected to #{host}:#{port}" }
					block_given? ? block.call(socket) : nil
				rescue ::IO::WaitReadable
					Logger.trace { "Waiting for read to #{host}:#{port}" }
					raise Timeout unless IO.select [socket], nil, nil, TCP_TIMEOUT
					retry
				rescue ::IO::WaitWritable
					Logger.trace { "Waiting for write to #{host}:#{port}" }
					raise Timeout unless IO.select nil, [socket], nil, TCP_TIMEOUT
					retry
				rescue => e
					case e.message
						when /^Connection refused/
							raise TLSNotAvailableException, e
					end
					raise
				ensure
					socket.close
				end
			end

			def ssl_connect(socket, context, method, &block)
				ssl_socket          = ::OpenSSL::SSL::SSLSocket.new socket, context
				ssl_socket.hostname = @hostname unless method == :SSLv2
				Logger.trace { "SSL connecting to #{@hostname}:#{@port}" }
				begin
					ssl_socket.connect_nonblock
					Logger.trace { "SSL connected to #{@hostname}:#{@port}" }
					return block_given? ? block.call(ssl_socket) : nil
				rescue ::IO::WaitReadable
					Logger.trace { "Waiting for SSL read to #{@hostname}:#{@port}" }
					raise TLSTimeout unless IO.select [socket], nil, nil, SSL_TIMEOUT
					retry
				rescue ::IO::WaitWritable
					Logger.trace { "Waiting for SSL write to #{@hostname}:#{@port}" }
					raise TLSTimeout unless IO.select nil, [socket], nil, SSL_TIMEOUT
					retry
				rescue ::OpenSSL::SSL::SSLError => e
					case e.message
						when /state=SSLv2 read server hello A$/,
								/state=SSLv3 read server hello A: wrong version number$/
							raise MethodNotAvailable, e
						when /state=error: no ciphers available$/,
								/state=SSLv3 read server hello A: sslv3 alert handshake failure$/
							raise CipherNotAvailable, e
					end
					raise TLSException, e
				rescue => e
					case e.message
						when /^Connection reset by peer$/
							raise MethodNotAvailable, e
					end
					raise TLSException, e
				ensure
					ssl_socket.close
				end
			end

			def ssl_client(method, ciphers = nil, &block)
				ssl_context         = ::OpenSSL::SSL::SSLContext.new method
				ssl_context.ciphers = ciphers if ciphers
				Logger.trace { "Try #{method} connection with #{ciphers}" }

				[::Socket::AF_INET, ::Socket::AF_INET6].each do |family|
					Logger.trace { "Try connection for family #{family}" }
					addrs = begin
						::Socket.getaddrinfo @hostname, nil, family, :STREAM
					rescue ::SocketError => e
						Logger.error { "Unable to resolv #{@hostname} : #{e}" }
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

				Logger.debug { "No SSL available on #{@hostname}" }
				raise CipherNotAvailable
			end

			def extract_cert
				EXISTING_METHODS.each do |method|
					next unless SUPPORTED_METHODS.include? method
					begin
						@cert, @chain = ssl_client(method) { |s| [s.peer_cert, s.peer_cert_chain] }
						Logger.debug { "Certificate #{@cert.subject}" }
						break
					rescue TLSException
					end
				end
				raise TLSNotAvailableException unless @cert
				@cert_valid   = ::OpenSSL::SSL.verify_certificate_identity @cert, @hostname
				@cert_trusted = verify_trust @chain, @cert
			end

			def prefered_cipher(method)
				cipher = ssl_client(method, 'ALL:COMPLEMENTOFALL') { |s| s.cipher }
				Logger.info { "Prefered cipher for #{Tls.colorize method} : #{Tls.colorize cipher.first}" }
				cipher
			rescue TLSException => e
				Logger.debug { "Method #{Tls.colorize method} not supported : #{e}" }
				nil
			end

			def fetch_prefered_ciphers
				Logger.info { '' }
				@prefered_ciphers = {}
				EXISTING_METHODS.each do |method|
					next unless SUPPORTED_METHODS.include? method
					@prefered_ciphers[method] = prefered_cipher method
				end
				raise TLSNotAvailableException unless @prefered_ciphers.any? { |_, c| !c.nil? }
			end

			def available_ciphers(method)
				context         = ::OpenSSL::SSL::SSLContext.new method
				context.ciphers = 'ALL:COMPLEMENTOFALL'
				context.ciphers
			end

			def supported_cipher?(method, cipher)
				ssl_client method, [cipher]
				Logger.info { "#{Tls.colorize method} / #{Tls.colorize cipher[0]} : Supported" }
				true
			rescue TLSException => e
				Logger.debug { "#{Tls.colorize method} / #{Tls.colorize cipher[0]} : Not supported (#{e})" }
				false
			end

			def check_supported_cipher
				Logger.info { '' }
				@supported_ciphers = {}
				EXISTING_METHODS.each do |method|
					next unless SUPPORTED_METHODS.include? method and @prefered_ciphers[method]
					ciphers = available_ciphers(method).select { |cipher| supported_cipher? method, cipher }
					@supported_ciphers[method] = ciphers
					Logger.info { '' } unless ciphers.empty?
				end
			end

			def verify_trust(chain, cert)
				store         = ::OpenSSL::X509::Store.new
				store.purpose = OpenSSL::X509::PURPOSE_SSL_CLIENT
				store.set_default_paths

				%w(cacert).each do |directory|
					::Dir.glob(::File.join '/usr/share/ca-certificates', directory, '*').each do |file|
						cert = ::OpenSSL::X509::Certificate.new ::File.read file
						begin
							store.add_cert cert
						rescue ::OpenSSL::X509::StoreError
						end
					end
				end
				chain.each do |cert|
					begin
						store.add_cert cert
					rescue ::OpenSSL::X509::StoreError
					end
				end
				trusted = store.verify cert
				p store.error_string unless trusted
				trusted
			end
		end

		class TcpServer < Server
			private
			def sock_type
				::Socket::SOCK_STREAM
			end
		end

		class UdpServer < Server
			private
			def sock_type
				::Socket::SOCK_DGRAM
			end
		end
	end
end

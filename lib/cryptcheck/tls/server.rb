require 'socket'
require 'openssl'
require 'httparty'

module CryptCheck
	module Tls
		class Server
			TCP_TIMEOUT       = 10
			SSL_TIMEOUT       = 2*TCP_TIMEOUT
			EXISTING_METHODS  = %i(TLSv1_2 TLSv1_1 TLSv1 SSLv3 SSLv2)
			SUPPORTED_METHODS = ::OpenSSL::SSL::SSLContext::METHODS
			class TLSException < ::StandardError
			end
			class TLSNotAvailableException < TLSException
				def to_s
					'TLS seems not supported on this server'
				end
			end
			class MethodNotAvailable < TLSException
			end
			class CipherNotAvailable < TLSException
			end
			class InappropriateFallback < TLSException
			end
			class Timeout < ::StandardError
			end
			class TLSTimeout < Timeout
			end
			class ConnectionError < ::StandardError
			end

			attr_reader :family, :ip, :port, :hostname, :prefered_ciphers, :cert, :cert_valid, :cert_trusted, :dh

			def initialize(hostname, family, ip, port)
				@hostname, @family, @ip, @port = hostname, family, ip, port
				@dh                            = []
				Logger.info { name.colorize :perfect }
				extract_cert
				Logger.info { '' }
				Logger.info { "Key : #{Tls.key_to_s self.key}" }
				fetch_prefered_ciphers
				check_supported_cipher
				check_fallback_scsv
				uniq_dh
			end

			def key
				@cert.public_key
			end

			def cipher_size
				supported_ciphers.collect { |c| c.size }.min
			end

			def supported_protocols
				@supported_ciphers.keys
			end

			def supported_ciphers
				@supported_ciphers.values.flatten 1
			end

			def supported_ciphers_by_protocol(protocol)
				@supported_ciphers[protocol]
			end

			EXISTING_METHODS.each do |method|
				class_eval <<-RUBY_EVAL, __FILE__, __LINE__ + 1
					def #{method.to_s.downcase}?
						!prefered_ciphers[:#{method}].nil?
					end
				RUBY_EVAL
			end

			SIGNATURE_ALGORITHMS = {
					'dsaWithSHA'                             => %i(sha1 dss),
					'dsaWithSHA1'                            => %i(sha1 dss),
					'dsaWithSHA1_2'                          => %i(sha1 dss),
					'dsa_with_SHA224'                        => %i(sha2 dss),
					'dsa_with_SHA256'                        => %i(sha2 dss),

					'mdc2WithRSA'                            => %i(mdc2 rsa),

					'md2WithRSAEncryption'                   => %i(md2 rsa),

					'md4WithRSAEncryption'                   => %i(md4, rsa),

					'md5WithRSA'                             => %i(md5 rsa),
					'md5WithRSAEncryption'                   => %i(md5 rsa),

					'shaWithRSAEncryption'                   => %i(sha rsa),
					'sha1WithRSA'                            => %i(sha1 rsa),
					'sha1WithRSAEncryption'                  => %i(sha1 rsa),
					'sha224WithRSAEncryption'                => %i(sha2 rsa),
					'sha256WithRSAEncryption'                => %i(sha2 rsa),
					'sha384WithRSAEncryption'                => %i(sha2 rsa),
					'sha512WithRSAEncryption'                => %i(sha2 rsa),

					'ripemd160WithRSA'                       => %i(ripemd160 rsa),

					'ecdsa-with-SHA1'                        => %i(sha1 ecc),
					'ecdsa-with-SHA224'                      => %i(sha2 ecc),
					'ecdsa-with-SHA256'                      => %i(sha2 ecc),
					'ecdsa-with-SHA384'                      => %i(sha2 ecc),
					'ecdsa-with-SHA512'                      => %i(sha2 ecc),

					'id_GostR3411_94_with_GostR3410_2001'    => %i(ghost),
					'id_GostR3411_94_with_GostR3410_94'      => %i(ghost),
					'id_GostR3411_94_with_GostR3410_94_cc'   => %i(ghost),
					'id_GostR3411_94_with_GostR3410_2001_cc' => %i(ghost)
			}

			%i(md2 mdc2 md4 md5 ripemd160 sha sha1 sha2 rsa dss ecc ghost).each do |name|
				class_eval <<-RUBY_EVAL, __FILE__, __LINE__ + 1
					def #{name}_sig?
						SIGNATURE_ALGORITHMS[@cert.signature_algorithm].include? :#{name}
					end
				RUBY_EVAL
			end

			Cipher::TYPES.each do |type, _|
				class_eval <<-RUBY_EVAL, __FILE__, __LINE__ + 1
					def #{type}?
						supported_ciphers.any? { |c| c.#{type}? }
					end
				RUBY_EVAL
			end

			def key_size
				@cert.public_key.size
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

			def tlsv1_2_only?
				tlsv1_2? and not ssl? and not tlsv1? and not tlsv1_1?
			end

			def pfs?
				supported_ciphers.any? { |c| c.pfs? }
			end

			def pfs_only?
				supported_ciphers.all? { |c| c.pfs? }
			end

			def ecdhe?
				supported_ciphers.any? { |c| c.ecdhe? }
			end

			def ecdhe_only?
				supported_ciphers.all? { |c| c.ecdhe? }
			end

			def aead?
				supported_ciphers.any? { |c| c.aead? }
			end

			def aead_only?
				supported_ciphers.all? { |c| c.aead? }
			end

			def sweet32?
				supported_ciphers.any? { |c| c.sweet32? }
			end

			def fallback_scsv?
				@fallback_scsv
			end

			def must_staple?
				@cert.extensions.any? { |e| e.oid == '1.3.6.1.5.5.7.1.24' }
			end

			private
			def name
				name = "#@ip:#@port"
				name += " [#@hostname]" if @hostname
				name
			end

			def connect(&block)
				socket   = ::Socket.new @family, sock_type
				sockaddr = ::Socket.sockaddr_in @port, @ip
				#Logger.trace { "Connecting to #{@ip}:#{@port}" }
				begin
					status = socket.connect_nonblock sockaddr
					#Logger.trace { "Connecting to #{@ip}:#{@port} status : #{status}" }
					raise ConnectionError, status unless status == 0
					#Logger.trace { "Connected to #{@ip}:#{@port}" }
					block_given? ? block.call(socket) : nil
				rescue ::IO::WaitReadable
					#Logger.trace { "Waiting for read to #{@ip}:#{@port}" }
					raise Timeout, "Timeout when connect to #{@ip}:#{@port} (max #{TCP_TIMEOUT.humanize})" unless IO.select [socket], nil, nil, TCP_TIMEOUT
					retry
				rescue ::IO::WaitWritable
					#Logger.trace { "Waiting for write to #{@ip}:#{@port}" }
					raise Timeout, "Timeout when connect to #{@ip}:#{@port} (max #{TCP_TIMEOUT.humanize})" unless IO.select nil, [socket], nil, TCP_TIMEOUT
					retry
				ensure
					socket.close
				end
			end

			def ssl_connect(socket, context, method, &block)
				ssl_socket          = ::OpenSSL::SSL::SSLSocket.new socket, context
				ssl_socket.hostname = @hostname if @hostname and method != :SSLv2
				#Logger.trace { "SSL connecting to #{name}" }
				begin
					ssl_socket.connect_nonblock
					#Logger.trace { "SSL connected to #{name}" }
					return block_given? ? block.call(ssl_socket) : nil
				rescue ::OpenSSL::SSL::SSLErrorWaitReadable
					#Logger.trace { "Waiting for SSL read to #{name}" }
					raise TLSTimeout, "Timeout when TLS connect to #{@ip}:#{@port} (max #{SSL_TIMEOUT.humanize})" unless IO.select [ssl_socket], nil, nil, SSL_TIMEOUT
					retry
				rescue ::OpenSSL::SSL::SSLErrorWaitWritable
					#Logger.trace { "Waiting for SSL write to #{name}" }
					raise TLSTimeout, "Timeout when TLS connect to #{@ip}:#{@port} (max #{SSL_TIMEOUT.humanize})" unless IO.select nil, [ssl_socket], nil, SSL_TIMEOUT
					retry
				rescue ::OpenSSL::SSL::SSLError => e
					case e.message
						when /state=SSLv.* read server hello A$/
							raise TLSNotAvailableException, e
						when /state=SSLv.* read server hello A: wrong version number$/
							raise MethodNotAvailable, e
						when /state=error: no ciphers available$/,
								/state=SSLv.* read server hello A: sslv.* alert handshake failure$/
							raise CipherNotAvailable, e
						when /state=SSLv.* read server hello A: tlsv.* alert inappropriate fallback$/
							raise InappropriateFallback, e
					end
					raise
				rescue ::SystemCallError => e
					case e.message
						when /^Connection reset by peer - SSL_connect$/
							raise TLSNotAvailableException, e
					end
					raise
				ensure
					ssl_socket.close
				end
			end

			# secp192r1 secp256r1
			SUPPORTED_CURVES = %w(secp160k1 secp160r1 secp160r2 sect163k1
				sect163r1 sect163r2 secp192k1 sect193r1 sect193r2 secp224k1
				secp224r1 sect233k1 sect233r1 sect239k1 secp256k1 sect283k1
				sect283r1 secp384r1 sect409k1 sect409r1 secp521r1 sect571k1
				sect571r1 X25519)

			def ssl_client(method, ciphers = %w(ALL COMPLEMENTOFALL), curves = nil, fallback: false, &block)
				ssl_context = ::OpenSSL::SSL::SSLContext.new method #, fallback_scsv: fallback
				ssl_context.enable_fallback_scsv if fallback
				ssl_context.ciphers     = ciphers.join ':'

				ssl_context.ecdh_curves = curves.join ':' if curves
				#ssl_context.ecdh_auto = false
				#ecdh = OpenSSL::PKey::EC.new('sect163r1').generate_key
				#ssl_context.tmp_ecdh_callback = proc { ecdh }

				Logger.trace { "Try method=#{method} / ciphers=#{ciphers} / curves=#{curves} / scsv=#{fallback}" }
				connect do |socket|
					ssl_connect socket, ssl_context, method do |ssl_socket|
						return block_given? ? block.call(ssl_socket) : nil
					end
				end
			end

			def extract_cert
				EXISTING_METHODS.each do |method|
					next unless SUPPORTED_METHODS.include? method
					begin
						@cert, @chain = ssl_client(method) { |s| [s.peer_cert, s.peer_cert_chain] }
						Logger.debug { "Certificate #{@cert.subject}" }
						break
					rescue Timeout, TLSTimeout, ConnectionError, ::SystemCallError
						raise
					end
				end
				raise TLSNotAvailableException unless @cert
				@cert_valid   = ::OpenSSL::SSL.verify_certificate_identity @cert, (@hostname || @ip)
				@cert_trusted = verify_trust @chain, @cert
			end

			def prefered_cipher(method)
				cipher = ssl_client(method) { |s| Cipher.new method, s.cipher, s.tmp_key }
				Logger.info { "Prefered cipher for #{Tls.colorize method} : #{cipher.colorize}" }
				cipher
			rescue => e
				Logger.debug { "Method #{Tls.colorize method} not supported : #{e}" }
				nil
			end

			def fetch_prefered_ciphers
				@prefered_ciphers = {}
				EXISTING_METHODS.each do |method|
					next unless SUPPORTED_METHODS.include? method
					@prefered_ciphers[method] = prefered_cipher method
				end
				raise TLSNotAvailableException unless @prefered_ciphers.any? { |_, c| !c.nil? }
			end

			def available_ciphers(method)
				context         = ::OpenSSL::SSL::SSLContext.new method
				context.ciphers = %w(ALL COMPLEMENTOFALL)
				context.ciphers
			end

			def supported_cipher?(method, cipher, curves = nil)
				dh = ssl_client(method, [cipher], curves) { |s| s.tmp_key }
				@dh << dh if dh
				cipher = Cipher.new method, cipher, dh
				dh     = dh ? " (#{'PFS'.colorize :good} : #{Tls.key_to_s dh})" : ''

				states = cipher.states
				text   = %i(critical error warning good perfect best).collect do |s|
					states[s].collect { |t| t.to_s.colorize s }.join ' '
				end.reject &:empty?
				text   = text.join ' '

				Logger.info { "#{Tls.colorize method} / #{cipher.colorize}#{dh} [#{text}]" }

				cipher
			rescue => e
				cipher = Cipher.new method, cipher
				Logger.debug { "#{Tls.colorize method} / #{cipher.colorize} : Not supported (#{e})" }
				nil
			end

			def check_supported_cipher
				Logger.info { '' }
				@supported_ciphers = {}
				EXISTING_METHODS.each do |method|
					next unless SUPPORTED_METHODS.include? method and @prefered_ciphers[method]
					supported_ciphers = []

					available_ciphers = available_ciphers method
					available_ciphers.each do |c|
						cipher = Cipher.new method, c
						supported = supported_cipher? method, c.first
						if supported
							if cipher.ecdhe?
								SUPPORTED_CURVES.each do |curve|
									supported = supported_cipher? method, c.first, [curve]
									supported_ciphers << supported if supported
								end
							else
								supported_ciphers << supported
							end
						end
					end

					Logger.info { '' } unless supported_ciphers.empty?
					@supported_ciphers[method] = supported_ciphers
				end
			end

			def check_fallback_scsv
				@fallback_scsv = false

				methods = @prefered_ciphers.reject { |_, v| v.nil? }.keys
				if methods.size > 1
					# We will try to connect to the not better supported method
					method = methods[1]

					begin
						ssl_client method, fallback: true
					rescue InappropriateFallback
						@fallback_scsv = true
					end
				else
					@fallback_scsv = nil
				end

				text, color = case @fallback_scsv
								  when true
									  ['Supported', :good]
								  when false
									  ['Not supported', :error]
								  when nil
									  ['Not applicable', :unknown]
							  end
				Logger.info { "Fallback SCSV : #{text.colorize color}" }
			end

			def verify_trust(chain, cert)
				store         = ::OpenSSL::X509::Store.new
				store.purpose = OpenSSL::X509::PURPOSE_SSL_CLIENT
				store.set_default_paths

				%w(/etc/ssl/certs).each do |directory|
					::Dir.glob(::File.join directory, '*.pem').each do |file|
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

			def uniq_dh
				dh, find = [], []
				@dh.each do |k|
					f = [k.type, k.size]
					unless find.include? f
						dh << k
						find << f
					end
				end
				@dh = dh
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

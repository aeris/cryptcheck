require 'socket'
require 'openssl'
require 'httparty'

module CryptCheck
	module Tls
		class Server
			TCP_TIMEOUT = 10
			SSL_TIMEOUT = 2*TCP_TIMEOUT

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

			def initialize(hostname, family, ip, port)
				@hostname, @family, @ip, @port = hostname, family, ip, port
				@dh                            = []
				@chains                        = []

				@name = "#@ip:#@port"
				@name += " [#@hostname]" if @hostname

				Logger.info { @name.colorize :blue }

				fetch_supported_methods
				fetch_supported_ciphers
				fetch_ecdsa_certs
				fetch_supported_curves

				fetch_ciphers_preferences

				# verify_certs

				check_fallback_scsv
			end

			def supported_method?(method)
				ssl_client method
				Logger.info { "Method #{method} : supported" }
				true
			rescue TLSException
				Logger.debug { "Method #{method} : not supported" }
				false
			end

			def fetch_supported_methods
				Logger.info { '' }
				Logger.info { 'Supported methods' }
				@supported_methods = Method.select { |m| supported_method? m }
			end

			def supported_cipher?(method, cipher)
				connection = ssl_client method, cipher
				Logger.info { "Cipher #{cipher} : supported" }
				connection
			rescue TLSException
				Logger.debug { "Cipher #{cipher} : not supported" }
				nil
			end

			def fetch_supported_ciphers
				Logger.info { '' }
				Logger.info { 'Supported ciphers' }
				@supported_ciphers = @supported_methods.collect do |method|
					ciphers = Cipher[method].collect do |cipher|
						connection = supported_cipher? method, cipher
						next nil unless connection
						[cipher, connection]
					end.compact.to_h
					[method, ciphers]
				end.to_h
			end

			def fetch_ecdsa_certs
				@ecdsa_certs = {}

				@supported_ciphers.each do |method, ciphers|
					ecdsa = ciphers.keys.detect &:ecdsa?
					next unless ecdsa

					@ecdsa_certs = Curve.collect do |curve|
						begin
							connection  = ssl_client method, ecdsa, curves: curve
							cert, chain = connection.peer_cert, connection.peer_cert_chain
							[curve, { cert: cert, chain: chain }]
						rescue TLSException
							nil
						end
					end.compact.to_h

					break
				end
			end

			def fetch_supported_curves
				Logger.info { '' }
				Logger.info { 'Supported elliptic curves' }

				ecdsa_curve = @ecdsa_certs.keys.first
				if ecdsa_curve
					# If we have an ECDSA cipher, we need at least the certificate curve to do handshake,
					# but with lowest priority to check for ECHDE and not just ECDSA

					@supported_ciphers.each do |method, ciphers|
						ecdsa = ciphers.keys.detect &:ecdsa?
						next unless ecdsa
						@supported_curves = Curve.select do |curve|
							next true if curve == ecdsa_curve # ECDSA curve is always supported
							begin
								connection = ssl_client method, ecdsa, curves: [curve, ecdsa_curve]
								# Not too fast !!!
								# Handshake will **always** succeed, because ECDSA curve is always supported
								# So, need to test for the real curve
								dh         = connection.tmp_key
								curve      = dh.curve
								supported  = curve != ecdsa_curve
								if supported
									Logger.info { "ECC curve #{curve} : supported" }
								else
									Logger.debug { "ECC curve #{curve} : not supported" }
								end
								supported
							rescue TLSException
								false
							end
						end
						break
					end
				else
					# If we have no ECDSA ciphers, ECC supported are only ECDH ones
					# So peak an ECDH cipher and test all curves
					@supported_ciphers.each do |method, ciphers|
						ecdh = ciphers.keys.detect { |c| c.ecdh? or c.ecdhe? }
						next unless ecdh
						@supported_curves = Curve.select do |curve|
							begin
								ssl_client method, ecdh, curves: curve
								Logger.info { "ECC curve #{curve} : supported" }
							rescue TLSException
								Logger.debug { "ECC curve #{curve} : not supported" }
								false
							end
						end
						break
					end
				end
			end

			def fetch_ciphers_preferences
				Logger.info { '' }
				Logger.info { 'Server preferences' }

				@preferences = @supported_ciphers.collect do |method, ciphers|
					ciphers = ciphers.keys
					if ciphers.size < 2
						Logger.info { "Preference not applicable for #{method}" }
					else
						a, b, _ = ciphers
						ab      = ssl_client(method, [a, b]).cipher.first
						ba      = ssl_client(method, [b, a]).cipher.first
						if ab != ba
							Logger.info { 'Server use client preference for '.colorize(:warning) + method.to_s }
							:client
						else
							sort        = -> (a, b) do
								connection = ssl_client method, [a, b]
								cipher     = connection.cipher.first
								cipher == a.name ? -1 : 1
							end
							preferences = ciphers.sort &sort
							Logger.info { "Cipher preference for #{method} is #{preferences.collect { |c| c.to_s :short }.join ':'}" }
							preferences
						end
					end
					[method, preferences]
				end.to_h
			end

			def check_fallback_scsv
				Logger.info { '' }

				@fallback_scsv = false
				if @supported_methods.size > 1
					# We will try to connect to the not better supported method
					method = @supported_methods[1]

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
									  ['supported', :good]
								  when false
									  ['not supported', :error]
								  when nil
									  ['not applicable', :unknown]
							  end
				Logger.info { 'Fallback SCSV : ' + text.colorize(color) }
			end

			Method.each do |method|
				method = method.name
				class_eval <<-RUBY_EVAL, __FILE__, __LINE__ + 1
					def #{method.to_s.downcase}?
						@supported_methods.detect { |m| m.name == method } 
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
						when /state=SSLv3 read server hello A$/,
								/state=SSLv3 read server hello A: wrong version number$/,
								/state=SSLv3 read server hello A: tlsv1 alert protocol version$/
							raise MethodNotAvailable, e
						when /state=SSLv2 read server hello A: peer error no cipher/,
								/state=error: no ciphers available$/,
								/state=SSLv3 read server hello A: sslv3 alert handshake failure$/,
								/state=error: missing export tmp dh key/
							raise CipherNotAvailable, e
						when /state=SSLv3 read server hello A: tlsv1 alert inappropriate fallback$/
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

			def ssl_client(method, ciphers = nil, curves: nil, fallback: false, &block)
				method      = method.name
				ssl_context = ::OpenSSL::SSL::SSLContext.new method
				ssl_context.enable_fallback_scsv if fallback

				if ciphers
					ciphers = [ciphers] unless ciphers.is_a? Enumerable
					ciphers = ciphers.collect(&:name).join ':'
				else
					ciphers = Cipher::ALL
				end
				ssl_context.ciphers = ciphers

				if curves
					curves                  = [curves] unless curves.is_a? Enumerable
					curves                  = curves.collect(&:name).join ':'
					ssl_context.ecdh_curves = curves
				end

				Logger.trace { "Try method=#{method} / ciphers=#{ciphers} / curves=#{curves} / scsv=#{fallback}" }
				connect do |socket|
					ssl_connect socket, ssl_context, method do |ssl_socket|
						return block_given? ? block.call(ssl_socket) : ssl_socket
					end
				end
			end

			def verify_certs
				Logger.info { '' }

				view = {}
				@chains.each do |cert, chain|
					id = cert.subject, cert.serial, cert.issuer
					next if view.include? id
					subject, serial, issuer = id
					key                     = cert.public_key

					Logger.info { "Certificate #{subject} [#{serial}] issued by #{issuer}" }
					Logger.info { "Key : #{Tls.key_to_s key }" }
					valid    = ::OpenSSL::SSL.verify_certificate_identity cert, (@hostname || @ip)
					trusted  = verify_trust chain, cert
					view[id] = { cert: cert, chain: chain, key: key, valid: valid, trusted: trusted }
				end
				@chains = view.values
				@keys   = @chains.collect { |c| c[:key] }
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

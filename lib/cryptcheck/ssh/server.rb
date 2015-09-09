require 'socket'

module CryptCheck
	module Ssh
		class SshNotSupportedServer
			attr_reader :hostname, :port

			def initialize(hostname, port)
				@hostname, @port = hostname, port
			end
		end

		class Server
			TCP_TIMEOUT = 10
			class SshNotAvailableException < Exception
			end

			attr_reader :hostname, :port, :kex, :encryption, :hmac, :compression, :key

			KEX = {
					'curve25519-sha256@libssh.org'         => :green,
					'ecdh-sha2-nistp521'                   => nil,		# NIST
					'ecdh-sha2-nistp384'                   => nil,		# NIST
					'ecdh-sha2-nistp256'                   => nil,		# NIST
					'diffie-hellman-group-exchange-sha256' => :green,	# DLP (PFS)
					'diffie-hellman-group-exchange-sha1'   => :yellow,	# DLP (PFS)
					'diffie-hellman-group14-sha1'          => :yellow,	# 2048 bits < 3072 bits
					'diffie-hellman-group1-sha1'           => :red		# 768 bits < 1024 bits
			}

			ENCRYPTION = {
					'chacha20-poly1305@openssh.com' => :green,
					'aes256-gcm@openssh.com'        => :green,
					'aes128-gcm@openssh.com'        => :green,
					'aes256-ctr'                    => nil,		# CTR < GCM
					'aes192-ctr'                    => nil,		# CTR < GCM
					'aes128-ctr'                    => nil,		# CTR < GCM
					'aes256-cbc'                    => :yellow,	# CBC
					'aes192-cbc'                    => :yellow,	# CBC
					'aes128-cbc'                    => :yellow,	# CBC
					'blowfish-cbc'                  => :yellow,	# CBC
					'cast128-cbc'                   => :yellow,	# CBC
					'3des-cbc'                      => :red,	# 3DES
					'arcfour'                       => :red,	# RC4
					'arcfour128'                    => :red,	# RC4
					'arcfour256'                    => :red		# RC4
			}

			HMAC = {
					'hmac-sha2-512-etm@openssh.com'  => :green,
					'hmac-sha2-256-etm@openssh.com'  => :green,
					'hmac-sha2-512'                  => nil,
					'hmac-sha2-256'                  => nil,
					'hmac-sha1-etm@openssh.com'      => :green,
					'hmac-sha1'                      => nil,
					'hmac-sha1-96-etm@openssh.com'   => :red,	# EXPORT
					'hmac-sha1-96'                   => :red,	# EXPORT
					'hmac-ripemd160-etm@openssh.com' => :green,
					'hmac-ripemd160'                 => nil,
					'hmac-md5-etm@openssh.com'       => :red,	# MD5
					'hmac-md5'                       => :red,	# MD5
					'hmac-md5-96-etm@openssh.com'    => :red,	# MD5 + EXPORT
					'hmac-md5-96'                    => :red,	# MD5 + EXPORT
					'umac-128-etm@openssh.com'       => :green,
					'umac-128@openssh.com'           => nil,
					'umac-64-etm@openssh.com'        => :red,	# < 128 bits
					'umac-64@openssh.com'            => :red	# < 128 bits
			}

			COMPRESSION = {
					'none'             => nil,
					'zlib@openssh.com' => nil
			}

			KEY = {
					'ssh-ed25519'                              => :green,
					'ssh-ed25519-cert-v01@openssh.com'         => :green,
					'ecdsa-sha2-nistp256'                      => nil,		# NIST
					'ecdsa-sha2-nistp384'                      => nil,		# NIST
					'ecdsa-sha2-nistp521'                      => nil,		# NIST
					'ssh-rsa'                                  => :yellow,	# RSA
					'ssh-dss'                                  => :red,		# DSA
					'ecdsa-sha2-nistp256-cert-v01@openssh.com' => nil,		# NIST
					'ecdsa-sha2-nistp384-cert-v01@openssh.com' => nil,		# NIST
					'ecdsa-sha2-nistp521-cert-v01@openssh.com' => nil,		# NIST
					'ssh-rsa-cert-v01@openssh.com'             => :yellow,	# RSA
					'ssh-rsa-cert-v00@openssh.com'             => :yellow,	# RSA
					'ssh-dss-cert-v01@openssh.com'             => :red,		# DSA
					'ssh-dss-cert-v00@openssh.com'             => :red,		# DSA
			}

			def initialize(hostname, port)
				@hostname, @port = hostname, port

				Logger.info { "#{hostname}:#{port}".colorize :blue }
				kex = ::Socket.tcp hostname, port, connect_timeout: TCP_TIMEOUT do |socket|
					socket.readline
					socket.write "SSH-2.0-CryptCheck\r\n"
					Packet.read_kex_init socket
				end

				@kex, @encryption, @hmac, @compression, @key = kex[:kex], kex[:encryption], kex[:mac], kex[:compression], kex[:host_key]

				Logger.info { '' }
				@kex.each { |k| Logger.info { "Key exchange : #{k.colorize KEX[k]}" } }
				Logger.info { '' }
				@encryption.each { |e| Logger.info { "Encryption : #{e.colorize ENCRYPTION[e]}" } }
				Logger.info { '' }
				@hmac.each { |h| Logger.info { "HMAC : #{h.colorize HMAC[h]}" } }
				Logger.info { '' }
				@compression.each { |c| Logger.info { "Compression : #{c}" } }
				Logger.info { '' }
				@key.each { |k| Logger.info { "Key type : #{k.colorize KEY[k]}" } }
			rescue => e
				Logger.debug { "SSH not supported : #{e}" }
				raise SshNotAvailableException, e
			end
		end
	end
end

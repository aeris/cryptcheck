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
					'diffie-hellman-group1-sha1'           => :yellow,
					'diffie-hellman-group14-sha1'          => :yellow,
					'diffie-hellman-group-exchange-sha1'   => :yellow,
					'diffie-hellman-group-exchange-sha256' => :green,
					'ecdh-sha2-nistp256'                   => :yellow,
					'ecdh-sha2-nistp384'                   => :yellow,
					'ecdh-sha2-nistp521'                   => :yellow
			}

			ENCRYPTION = {
					'3des-cbc'                      => :red,
					'aes128-cbc'                    => :yellow,
					'aes192-cbc'                    => :yellow,
					'aes256-cbc'                    => :yellow,
					'aes128-ctr'                    => :yellow,
					'aes192-ctr'                    => :yellow,
					'aes256-ctr'                    => :yellow,
					'aes128-gcm@openssh.com'        => :green,
					'aes256-gcm@openssh.com'        => :green,
					'arcfour'                       => :red,
					'arcfour128'                    => :red,
					'arcfour256'                    => :red,
					'blowfish-cbc'                  => :yellow,
					'cast128-cbc'                   => nil,
					'chacha20-poly1305@openssh.com' => :green
			}

			HMAC = {
					'hmac-md5'                       => :red,
					'hmac-md5-96'                    => :red,
					'hmac-ripemd160'                 => :green,
					'hmac-sha1'                      => :yellow,
					'hmac-sha1-96'                   => :red,
					'hmac-sha2-256'                  => :green,
					'hmac-sha2-512'                  => :green,
					'umac-64@openssh.com'            => :red,
					'umac-128@openssh.com'           => nil,
					'hmac-md5-etm@openssh.com'       => :red,
					'hmac-md5-96-etm@openssh.com'    => :red,
					'hmac-ripemd160-etm@openssh.com' => :green,
					'hmac-sha1-etm@openssh.com'      => :yellow,
					'hmac-sha1-96-etm@openssh.com'   => :red,
					'hmac-sha2-256-etm@openssh.com'  => :green,
					'hmac-sha2-512-etm@openssh.com'  => :green,
					'umac-64-etm@openssh.com'        => :red,
					'umac-128-etm@openssh.com'       => nil
			}

			COMPRESSION = {
					'none'             => nil,
					'zlib@openssh.com' => nil
			}

			KEY = {
					'ecdsa-sha2-nistp256-cert-v01@openssh.com' => :yellow,
					'ecdsa-sha2-nistp384-cert-v01@openssh.com' => :yellow,
					'ecdsa-sha2-nistp521-cert-v01@openssh.com' => :yellow,
					'ssh-ed25519-cert-v01@openssh.com'         => :green,
					'ssh-rsa-cert-v01@openssh.com'             => :yellow,
					'ssh-dss-cert-v01@openssh.com'             => :red,
					'ssh-rsa-cert-v00@openssh.com'             => :yellow,
					'ssh-dss-cert-v00@openssh.com'             => :red,
					'ecdsa-sha2-nistp256'                      => :yellow,
					'ecdsa-sha2-nistp384'                      => :yellow,
					'ecdsa-sha2-nistp521'                      => :yellow,
					'ssh-ed25519'                              => :green,
					'ssh-rsa'                                  => :yellow,
					'ssh-dss'                                  => :red
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

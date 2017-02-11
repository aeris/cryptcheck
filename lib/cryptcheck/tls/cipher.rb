module CryptCheck
	module Tls
		class Cipher
			TYPES = {
					md5:       %w(MD5),
					sha1:      %w(SHA),
					sha256:    %w(SHA256),
					sha384:    %w(SHA384),
					poly1305:  %w(POLY1305),

					psk:       %w(PSK),
					srp:       %w(SRP),
					anonymous: %w(ADH AECDH),
					dss:       %w(DSS),
					rsa:       %w(RSA),
					ecdsa:     %w(ECDSA),
					dh:        %w(DH ADH),
					ecdh:      %w(ECDH AECDH),
					dhe:       %w(DHE EDH ADH),
					ecdhe:     %w(ECDHE AECDH),

					null:      %w(NULL),
					export:    %w(EXP),
					rc2:       %w(RC2),
					rc4:       %w(RC4),
					des:       %w(DES-CBC),
					des3:      %w(3DES DES-CBC3),
					aes:       %w(AES(128|256) AES-(128|256)),
					camellia:  %w(CAMELLIA(128|256)),
					seed:      %w(SEED),
					idea:      %w(IDEA),
					chacha20:  %w(CHACHA20),

					#cbc:       %w(CBC),
					gcm:       %w(GCM),
					ccm:       %w(CCM)
			}

			attr_reader :method, :name

			def initialize(method, name)
				@method, @name = method, name
			end

			extend Enumerable

			def self.each(&block)
				SUPPORTED.each &block
			end

			def self.[](method)
				SUPPORTED[method]
			end

			TYPES.each do |name, ciphers|
				class_eval <<-RUBY_EVAL, __FILE__, __LINE__ + 1
				def self.#{name}?(cipher)
					#{ciphers}.any? { |c| /(^|-)#\{c\}(-|$)/ =~ cipher }
				end
				def #{name}?
					#{ciphers}.any? { |c| /(^|-)#\{c\}(-|$)/ =~ @name }
				end
				RUBY_EVAL
			end

			def self.cbc?(cipher)
				!aead? cipher
			end

			def cbc?
				!aead?
			end

			def self.aead?(cipher)
				gcm?(cipher) or ccm?(cipher)
			end

			def aead?
				gcm? or ccm?
			end

			def ssl?
				sslv2? or sslv3?
			end

			def tls?
				tlsv1? or tlsv1_1? or tlsv1_2?
			end

			def pfs?
				dhe? or ecdhe?
			end

			def ecc?
				ecdsa? or ecdhe? or ecdh?
			end

			def sweet32?
				size = self.block_size
				return false unless size # Not block encryption
				size <= 64
			end

			def to_s(type = :long)
				case type
					when :long
						states = self.states.collect { |k, vs| vs.collect { |v| v.to_s.colorize k } }.flatten.join ' '
						"#{@method} #{@name.colorize self.status} [#{states}]"
					when :short
						@name.colorize self.status
				end
			end

			def <=>(other)
				compare = State.compare self, other
				return compare unless compare == 0

				size_a, size_b = a.size, b.size
				compare        = size_b <=> size_a
				return compare unless compare == 0

				dh_a, dh_b = a.dh, b.dh
				return -1 if not dh_a and dh_b
				return 1 if dh_a and not dh_b
				return a.name <=> b.name if not dh_a and not dh_b

				compare = b.dh.size <=> a.dh.size
				return compare unless compare == 0

				a.name <=> b.name
			end

			def self.list(cipher_suite = 'ALL:COMPLEMENTOFALL', method: :TLSv1_2)
				context         = OpenSSL::SSL::SSLContext.new method
				context.ciphers = cipher_suite
				ciphers         = context.ciphers.collect { |c| self.new method, c }
				self.sort ciphers
			end

			def kex
				case
					when ecdhe? || ecdh?
						:ecdh
					when dhe? || dh?
						:dh
					when dss?
						:dss
					else
						:rsa
				end
			end

			def auth
				case
					when ecdsa?
						:ecdsa
					when rsa?
						:rsa
					when dss?
						:dss
					when anonymous?
						nil
					else
						:rsa
				end
			end

			def encryption
				case
					when chacha20?
						:chacha20
					when aes?
						:aes
					when camellia?
						:camellia
					when seed?
						:seed
					when idea?
						:idea
					when des3?
						:'3des'
					when des?
						:des
					when rc4?
						:rc4
					when rc2?
						:rc2
				end
			end

			def mode
				case
					when gcm?
						:gcm
					when ccm?
						:ccm
					when rc4? || chacha20?
						nil
					else
						:cbc
				end
			end

			def block_size
				case self.encryption
					when :'3des', :idea, :rc2
						64
					when :aes, :camellia, :seed
						128
					else
						nil
				end
			end

			def hmac
				case
					when poly1305?
						[:poly1305, 128]
					when sha384?
						[:sha384, 384]
					when sha256?
						[:sha256, 256]
					when sha1?
						[:sha1, 160]
					when md5?
						[:md5, 128]
				end
			end

			include State

			CHECKS = [
					[:dss, -> (c) { c.dss? }, :critical],
					[:anonymous, -> (c) { c.anonymous? }, :critical],
					[:null, -> (c) { c.null? }, :critical],
					[:export, -> (c) { c.export? }, :critical],
					[:des, -> (c) { c.des? }, :critical],
					[:md5, -> (c) { c.md5? }, :critical],

					[:rc4, -> (c) { c.rc4? }, :error],
					[:sweet32, -> (c) { c.sweet32? }, :error],

					[:no_pfs, -> (c) { not c.pfs? }, :warning],
					[:pfs, -> (c) { c.pfs? }, :good],
					[:dhe, -> (c) { c.dhe? }, :warning],
					[:ecdhe, -> (c) { c.ecdhe? }, :good],

					[:aead, -> (c) { c.aead? }, :good]
			].freeze

			def checks
				CHECKS
			end

			def <=>(other)
				status = State.compare self, other
				return status if status != 0
				@name <=> other.name
			end

			ALL       = 'ALL:COMPLEMENTOFALL'
			SUPPORTED = Method.collect do |m|
				context         = ::OpenSSL::SSL::SSLContext.new m.to_sym
				context.ciphers = ALL
				ciphers         = context.ciphers.collect { |c| Cipher.new m, c.first }
				[m, ciphers.sort]
			end.to_h.freeze
		end
	end
end

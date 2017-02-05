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

			attr_reader :method, :name, :states, :status

			def initialize(method, name)
				@method, @name = method, name
				fetch_states
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

			CHECKS = [
					[:psk, Proc.new { |s| s.psk? }, :critical],
					[:srp, Proc.new { |s| s.srp? }, :critical],
					[:dss, Proc.new { |s| s.dss? }, :critical],
					[:anonymous, Proc.new { |s| s.anonymous? }, :critical],
					[:null, Proc.new { |s| s.null? }, :critical],
					[:export, Proc.new { |s| s.export? }, :critical],
					[:des, Proc.new { |s| s.des? }, :critical],
					[:md5, Proc.new { |s| s.md5? }, :critical],

					[:rc4, Proc.new { |s| s.rc4? }, :error],
					[:sweet32, Proc.new { |s| s.sweet32? }, :error],

					#[:cbc, Proc.new { |s| s.cbc? }, :warning],
					[:dhe, Proc.new { |s| s.dhe? }, :warning],
					[:no_pfs, Proc.new { |s| not s.pfs? }, :warning],

					[:pfs, Proc.new { |s| s.pfs? }, :good],
					[:ecdhe, Proc.new { |s| s.ecdhe? }, :good],
					[:aead, Proc.new { |s| s.aead? }, :good],
			]

			def fetch_states
				@states = Status.collect { |s| [s, []] }.to_h
				CHECKS.each do |name, check, status|
					result = check.call self
					@states[status ? status : result] << name if result
				end
				statuses = @states.reject { |_, v| v.empty? }.keys
				@status  = Status[statuses]
			end

			def to_s(type = :long)
				case type
					when :long
						states = @states.collect { |k, vs| vs.collect { |v| v.to_s.colorize k } }.flatten.join ' '
						"#{@method} #{@name.colorize @status} [#{states}]"
					when :short
						@name.colorize @status
				end
			end

			PRIORITY = { good: 1, none: 2, warning: 3, error: 4, critical: 5 }

			def self.sort(ciphers)
				ciphers.sort do |a, b|
					error_a, error_b = PRIORITY[a.score], PRIORITY[b.score]
					compare          = error_a <=> error_b
					next compare unless compare == 0

					size_a, size_b = a.size, b.size
					compare        = size_b <=> size_a
					next compare unless compare == 0

					dh_a, dh_b = a.dh, b.dh
					next -1 if not dh_a and dh_b
					next 1 if dh_a and not dh_b
					next a.name <=> b.name if not dh_a and not dh_b

					compare = b.dh.size <=> a.dh.size
					next compare unless compare == 0

					a.name <=> b.name
				end
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

			def <=>(other)
				status = Status.compare self, other
				return status if status != 0
				@name <=> other.name
			end

			ALL       = 'ALL:COMPLEMENTOFALL'
			SUPPORTED = Method.collect do |m|
				context         = ::OpenSSL::SSL::SSLContext.new m.to_sym
				context.ciphers = ALL

				[m, context.ciphers.collect { |c| Cipher.new m, c.first }.sort ]
			end.to_h.freeze
		end
	end
end

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

			attr_reader :protocol, :name, :size, :key, :dh

			def initialize(protocol, cipher, dh=nil, key=nil)
				@protocol, @dh, @key    = protocol, dh, key
				@name, _, @size = cipher
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
			def aead?(cipher)
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

			def sweet32?
				enc = params[:enc]
				return false unless enc # No encryption
				block = enc[2]
				return false unless block # No block encryption
				block <= 64
			end

			def sweet32?
				enc = params[:enc]
				return false unless enc # No encryption
				block = enc[2]
				return false unless block # No block encryption
				block <= 64
			end

			def colorize
				@name.colorize self.score
			end

			CHECKS = [
					[:dss, Proc.new { |s| s.dss? }, :critical],
					[:anonymous, Proc.new { |s| s.anonymous? }, :critical],
					[:null, Proc.new { |s| s.null? }, :critical],
					[:export, Proc.new { |s| s.export? }, :critical],
					[:des, Proc.new { |s| s.des? }, :critical],
					[:md5, Proc.new { |s| s.md5? }, :critical],

					[:rc4, Proc.new { |s| s.rc4? }, :error],
					[:sweet32, Proc.new { |s| s.sweet32? }, :error],

					#[:cbc, Proc.new { |s| s.cbc? }, :warning],
					#[:dhe, Proc.new { |s| s.dhe? }, :warning],
					[:weak_dh, Proc.new do |s|
						dh = s.dh
						next nil unless dh
						status = dh.status
						next status if %i(critical error warning).include? status
						nil
					end ],
					[:no_pfs, Proc.new { |s| not s.pfs? }, :warning],

					[:pfs, Proc.new { |s| s.pfs? }, :good],
					[:ecdhe, Proc.new { |s| s.ecdhe? }, :good],
					[:aead, Proc.new { |s| s.aead? }, :good],
			]

			def states
				return @states if @states
				@states = { critical: [], error: [], warning: [], good: [], perfect: [], best: [] }
				CHECKS.each do |name, check, status|
					result = check.call self
					states[status ? status : result] << name if result
				end
				@states
			end

			def score
				%i(critical error warning good perfect best).each do |s|
					return s unless self.states[s].empty?
				end
				:none
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

			def self.list(cipher_suite = 'ALL:COMPLEMENTOFALL', protocol: :TLSv1_2)
				context         = OpenSSL::SSL::SSLContext.new protocol
				context.ciphers = cipher_suite
				ciphers         = context.ciphers.collect { |c| self.new protocol, c }
				self.sort ciphers
			end

			def params
				key_exchange   = case
									 when ecdhe? || ecdh?
										 [:ecdh, dh]
									 when dhe? || dh?
										 [:dh, dh]
									 when dss?
										 [:dss, key]
									 else
										 [:rsa, key]
								 end
				authentication = case
									 when ecdsa?
										 [:ecdsa, key]
									 when rsa?
										 [:rsa, key]
									 when dss?
										 [:dss, key]
									 when anonymous?
										 nil
									 else
										 [:rsa, key]
								 end
				encryption     = case
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
				mode           = case
									 when gcm?
										 :gcm
									 when ccm?
										 :ccm
									 when rc4? || chacha20?
										 nil
									 else
										 :cbc
								 end
				b              = case encryption
									 when :rc4
										 nil
									 when :'3des', :idea, :rc2
										 64
									 when :aes, :camellia, :seed
										 128
								 end
				encryption     = [encryption, size, b, mode] if encryption
				mac            = case
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
				{ kex: key_exchange, auth: authentication, enc: encryption, mac: mac, pfs: pfs? }
			end
		end
	end
end

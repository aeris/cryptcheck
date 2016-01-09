module CryptCheck
	module Tls
		class Cipher
			TYPES = {
					md5:       %w(MD5),
					sha1:      %w(SHA),

					psk:       %w(PSK),
					srp:       %w(SRP),
					anonymous: %w(ADH AECDH),

					dss:       %w(DSS),

					null:      %w(NULL),
					export:    %w(EXP),
					des:       %w(DES-CBC),
					rc2:       %w(RC2),
					rc4:       %w(RC4),
					des3:      %w(3DES DES-CBC3),

					pfs:       %w(DHE EDH ECDHE)
			}

			attr_reader :protocol, :name, :size, :dh

			def initialize(protocol, cipher, dh=nil)
				@protocol, @dh  = protocol, dh
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

			def ssl?
				sslv2? or sslv3?
			end

			def tls?
				tlsv1? or tlsv1_1? or tlsv1_2?
			end

			def colorize
				colors = case
							 when dss?,
									 anonymous?,
									 null?,
									 export?,
									 md5?,
									 des?,
									 rc4?
								 { color: :white, background: :red }
							 when des3?
								 { color: :yellow }
							 when pfs?
								 { color: :green }
						 end
				@name.colorize colors
			end

			def state
				ok = Proc.new { |n| self.send "#{n}?" }
				{
						success: %i(pfs).select { |n| ok.call n },
						warning: %i().select { |n| ok.call n },
						danger:  %i(des3).select { |n| ok.call n },
						error:   %i(dss md5 psk srp anonymous null export des rc2 rc4).select { |n| ok.call n }
				}
			end

			def score
				state = self.state
				return :error unless state[:error].empty?
				return :danger unless state[:danger].empty?
				return :warning unless state[:warning].empty?
				return :success unless state[:success].empty?
				:none
			end

			PRIORITY = { success: 1, none: 2, warning: 3, danger: 4, error: 5 }
			def self.sort(ciphers)
				ciphers.sort do |a, b|
					error_a, error_b = PRIORITY[a.score], PRIORITY[b.score]
					compare = error_a <=> error_b
					next compare unless compare == 0

					size_a, size_b = a.size, b.size
					compare = size_b <=> size_a
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
				context = OpenSSL::SSL::SSLContext.new protocol
				context.ciphers = cipher_suite
				ciphers = context.ciphers.collect { |c| self.new protocol, c }
				self.sort ciphers
			end
		end
	end
end

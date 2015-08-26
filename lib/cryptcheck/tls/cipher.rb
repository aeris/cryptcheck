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

					pfs:       %w(DHE EDH ECDHE ECDH)
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
				{ success: %i(pfs).select { |n| ok.call n },
				  warning: %i(des3 sha1).select { |n| ok.call n },
				  danger: %i(dss md5 psk srp anonymous null export des rc2 rc4).select { |n| ok.call n }
				}
			end
		end
	end
end

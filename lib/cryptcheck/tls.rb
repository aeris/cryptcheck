require 'erb'
require 'parallel'

module CryptCheck
	module Tls
		TLS_NOT_AVAILABLE = Proc.new { |host, port|
			TlsNotSupportedGrade.new TlsNotSupportedServer.new host, port
		}

		def self.analyze(host, port)
			::CryptCheck.analyze host, port do |family, ip, host|
				s = TcpServer.new family, ip, port, hostname: host
				g = Grade.new s
				Logger.info { '' }
				g.display
				g
			end
		end

		def self.colorize(cipher)
			colors = case
						 when /^SSL/ =~ cipher then { color: :white, background: :red }
						 when :TLSv1_2 == cipher then { color: :green }
					 end
			cipher.to_s.colorize colors
		end

		def self.key_to_s(key)
			size       = key.rsa_equivalent_size
			type_color = case key.type
							 when :ecc then { color: :green }
							 when :dsa then { color: :yellow }
						 end
			size_color = case size
							 when 0...1024 then { color: :white, background: :red }
							 when 1024...2048 then { color: :yellow }
							 when 4096...::Float::INFINITY then { color: :green }
						 end
			"#{key.type.to_s.upcase.colorize type_color} #{key.size.to_s.colorize size_color} bits"
		end
	end
end

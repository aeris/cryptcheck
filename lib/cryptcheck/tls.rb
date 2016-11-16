require 'erb'
require 'parallel'

module CryptCheck
	module Tls
		def self.analyze(host, port)
			::CryptCheck.analyze host, port, TcpServer, Grade
		end

		def self.colorize(cipher)
			colors = case
						 when /^SSL/ =~ cipher then :critical
						 when :TLSv1_2 == cipher then :good
					 end
			cipher.to_s.colorize colors
		end

		def self.key_to_s(key)
			type_color = case key.type
							 when :ecc then :good
							 when :dh then :warning
							 when :dsa then :critical
						 end
			"#{key.type.to_s.upcase.colorize type_color} #{key.size.to_s.colorize key.status} bits"
		end
	end
end

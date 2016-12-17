require 'erb'
require 'parallel'

module CryptCheck
	module Tls
		def self.analyze(host, port)
			::CryptCheck.analyze host, port, TcpServer, Grade
		end

		def self.colorize(cipher)
			colors = case
						 when /^SSL/ =~ cipher
							 :critical
						 when :TLSv1_2 == cipher
							 :good
					 end
			cipher.to_s.colorize colors
		end

		def self.key_to_s(key)
			size, color = case key.type
							 when :ecc
								 ["#{key.group.curve_name} #{key.size}", :good]
							 when :dh
								 [key.size, :warning]
							 when :dsa
								 [key.size, :critical]
						 end
			"#{key.type.to_s.upcase.colorize color} #{size.to_s.colorize key.status} bits"
		end
	end
end

require 'erb'
require 'parallel'

module CryptCheck
	module Tls
		def self.analyze(host, port)
			::CryptCheck.analyze host, port, TcpServer, Grade
		end

		def self.colorize(cipher)
			colors = case
						 when /^SSL/ =~ cipher then { color: :white, background: :red }
						 when :TLSv1_2 == cipher then { color: :green }
					 end
			cipher.to_s.colorize colors
		end

		def self.key_to_s(key)
			type_color = case key.type
							 when :ecc then { color: :green }
							 when :dsa then { color: :red }
						 end
			size_color = case key.status
							when :error then { color: :white, background: :red }
							when :warning then { color: :yellow }
							when :success then { color: :green }
						end
			"#{key.type.to_s.upcase.colorize type_color} #{key.size.to_s.colorize size_color} bits"
		end
	end
end

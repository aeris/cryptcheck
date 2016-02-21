module CryptCheck
	module Tls
		module Https
			def self.analyze(host, port=443)
				::CryptCheck.analyze host, port do |family, ip, host|
					s = Server.new family, ip, port, hostname: host
					g = Grade.new s
					Logger.info { '' }
					g.display
					g
				end
			end

			def self.analyze_file(input, output)
				::CryptCheck.analyze_file(input, 'output/https.erb', output) { |host| self.analyze host }
			end
		end
	end
end

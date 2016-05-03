module CryptCheck
	module Tls
		module Https
			def self.analyze(host, port=443)
				::CryptCheck.analyze host, port, Server, Grade
			end

			def self.analyze_file(input, output)
				::CryptCheck.analyze_file(input, 'output/https.erb', output) { |host| self.analyze host }
			end
		end
	end
end

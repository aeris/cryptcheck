module CryptCheck
	module Tls
		module Https
			def self.analyze(hosts, output)
				Tls.analyze hosts, 'output/https.erb', output, nil, port: 443, server_class: Server, grade_class: Grade
			end

			def self.analyze_from_file(file, output)
				Tls.analyze_from_file file, 'output/https.erb', output, port: 443, server_class: Server, grade_class: Grade
			end
		end
	end
end

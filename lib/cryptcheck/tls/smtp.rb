module CryptCheck
	module Tls
		module Smtp
			def self.analyze_from_file(file, output)
				Tls.analyze_from_file file, 'output/smtp.erb', output, port: 25, server_class: Server, grade_class: Grade
			end
		end
	end
end

module CryptCheck
	module Tls
		autoload :Server, 'cryptcheck/tls/server'
		autoload :Grade, 'cryptcheck/tls/grade'
		autoload :Https, 'cryptcheck/tls/https'

		module Https
			autoload :Server, 'cryptcheck/tls/https/server'
			autoload :Grade, 'cryptcheck/tls/https/grade'
		end
	end
end

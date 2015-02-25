module CryptCheck
	module Tls
		autoload :Server, 'cryptcheck/tls/server'
		autoload :TlsNotSupportedServer, 'cryptcheck/tls/server'
		autoload :Grade, 'cryptcheck/tls/grade'
		autoload :TlsNotSupportedGrade, 'cryptcheck/tls/grade'

		autoload :Https, 'cryptcheck/tls/https'
		module Https
			autoload :Server, 'cryptcheck/tls/https/server'
			autoload :Grade, 'cryptcheck/tls/https/grade'
		end

		autoload :Xmpp, 'cryptcheck/tls/xmpp'
		module Xmpp
			autoload :Server, 'cryptcheck/tls/xmpp/server'
			autoload :Grade, 'cryptcheck/tls/xmpp/grade'
		end
	end
end

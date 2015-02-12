module CryptCheck
	module Tls
		autoload :Server, 'cryptcheck/tls/server'
		autoload :Grade, 'cryptcheck/tls/grade'
		autoload :Https, 'cryptcheck/tls/https'
		autoload :Xmpp, 'cryptcheck/tls/xmpp'

		module Xmpp
			autoload :Server, 'cryptcheck/tls/xmpp/server'
			autoload :Grade, 'cryptcheck/tls/xmpp/grade'
		end
	end
end

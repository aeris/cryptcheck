require 'colorize'

module CryptCheck
	autoload :Logger, 'cryptcheck/logger'
	autoload :Tls, 'cryptcheck/tls'
	module Tls
		autoload :Server, 'cryptcheck/tls/server'
		autoload :TcpServer, 'cryptcheck/tls/server'
		autoload :UdpServer, 'cryptcheck/tls/server'
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

		autoload :Smtp, 'cryptcheck/tls/smtp'
		module Smtp
			autoload :Server, 'cryptcheck/tls/smtp/server'
			autoload :Grade, 'cryptcheck/tls/smtp/grade'
		end
	end
end

require 'resolv'

module CryptCheck
	module Tls
		module Https
			def self.analyze(hostname, port = 443)
				host = Host.new hostname, port
				Tls.aggregate host
			end
		end
	end
end

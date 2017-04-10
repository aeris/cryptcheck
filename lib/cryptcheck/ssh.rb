module CryptCheck
	module Ssh
		def self.analyze(host, port=22)
			::CryptCheck.analyze host, port, Server
		end
	end
end

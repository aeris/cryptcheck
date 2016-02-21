module CryptCheck
	module Ssh
		def self.analyze(host, port=22)
			::CryptCheck.analyze(host, port, Proc.new { SshNotSupportedServer.new host, port }) do |_, ip, host|
				Server.new ip, port, hostname: host
			end
		end
	end
end

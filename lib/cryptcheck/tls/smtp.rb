require 'resolv'

module CryptCheck
	module Tls
		module Smtp
			def self.analyze(hostname, port = 25)
				srv   = ::Resolv::DNS.new.getresources(hostname, ::Resolv::DNS::Resource::IN::MX)
								.sort_by &:preference
				hosts = if srv.empty?
							[hostname]
						else
							srv.collect { |s| s.exchange.to_s }
						end

				Tls.aggregate hosts.collect { |h| Host.new h, port }
			end
		end
	end
end

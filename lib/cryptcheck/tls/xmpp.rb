module CryptCheck
	module Tls
		module Xmpp
			def self.analyze(hostname, type = :s2s)
				service, port = case type
								when :s2s
									['_xmpp-server', 5269]
								when :c2s
									['_xmpp-client', 5222]
								end
				srv           = Resolv::DNS.new.getresources("#{service}._tcp.#{hostname}",
															 Resolv::DNS::Resource::IN::SRV)
										.sort_by &:priority
				hosts         = if srv.empty?
									[[hostname, port]]
								else
									srv.collect { |s| [s.target.to_s, s.port] }
								end

				Tls.aggregate hosts.collect { |args| Host.new *args, domain: hostname }
			end
		end
	end
end

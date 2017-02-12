module CryptCheck
	module Tls
		module Xmpp
			def self.analyze(host, port=nil, domain: nil, type: :s2s)
				domain ||= host
				::CryptCheck.analyze host, port, Server, Grade, domain: domain, type: type
			end

			def self.analyze_domain(domain, type: :s2s)
				service, port = case type
									when :s2s
										['_xmpp-server', 5269]
									when :c2s
										['_xmpp-client', 5222]
								end
				srv = Resolv::DNS.new.getresources("#{service}._tcp.#{domain}", Resolv::DNS::Resource::IN::SRV).sort_by &:priority
				hosts = srv.empty? ? [[domain, port]] : srv.collect { |s| [s.target.to_s, s.port] }
				results = {}
				hosts.each { |host, port| results.merge! self.analyze(host, port, domain: domain, type: type) }
				results
			end

			def self.analyze_file(input, output)
				::CryptCheck.analyze_file(input, 'output/xmpp.erb', output) { |host| self.analyze_domain host }
			end
		end
	end
end

module CryptCheck
	module Tls
		module Smtp
			def self.analyze(host, port=25, domain: nil)
				::CryptCheck.analyze host, port, Server, Grade, domain: domain
			end

			def self.analyze_domain(domain)
				srv = Resolv::DNS.new.getresources(domain, Resolv::DNS::Resource::IN::MX).sort_by &:preference
				hosts = srv.empty? ? [domain] : srv.collect { |s| s.exchange.to_s }
				hosts.collect { |h| self.analyze h, domain: domain }.flatten(1)
			end

			def self.analyze_file(input, output)
				::CryptCheck.analyze_file(input, 'output/smtp.erb', output) { |host| self.analyze_domain host }
			end
		end
	end
end

module CryptCheck
	module Tls
		module Smtp
			def self.analyze(host, port=25, domain: nil)
				domain ||= host
				::CryptCheck.analyze host, port do |family, ip, host|
					s = Server.new family, ip, port, hostname: host, domain: domain
					g = Grade.new s
					Logger.info { '' }
					g.display
					g
				end
			end

			def self.analyze_domain(domain)
				srv = Resolv::DNS.new.getresources(domain, Resolv::DNS::Resource::IN::MX).sort_by(&:preference).first
				hostname = srv ? srv.exchange.to_s : domain
				self.analyze hostname, domain: domain
			end

			def self.analyze_file(input, output)
				::CryptCheck.analyze_file(input, 'output/smtp.erb', output) { |host| self.analyze_domain host }
			end
		end
	end
end

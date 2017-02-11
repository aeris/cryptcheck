module CryptCheck
	module Tls
		module Https
			class Host < Tls::Host
				def initialize(hostname, port=443)
					@hostname, @port = hostname, port
					super()
				end

				private
				def resolve
					begin
						ip = IPAddr.new @hostname
						return [[nil, ip.to_s, ip.family]]
					rescue IPAddr::InvalidAddressError
					end
					::Addrinfo.getaddrinfo(@hostname, nil, nil, :STREAM)
							.collect { |a| [@hostname, a.ip_address, a.afamily] }
				end

				def server(hostname, ip, family)
					Https::Server.new hostname, ip, family, @port
				end

				def grade(server)
					Https::Grade.new server
				end
			end
		end
	end
end

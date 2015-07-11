require 'resolv'

module CryptCheck
	module Tls
		module Smtp
			class Server < Tls::TcpServer
				RESOLVER = Resolv::DNS.new

				attr_reader :domain

				def initialize(domain, port=25)
					@domain = domain
					srv = RESOLVER.getresources(domain, Resolv::DNS::Resource::IN::MX).sort_by(&:preference).first
					if srv
						hostname = srv.exchange.to_s
					else # DNS is not correctly set, guess config…
						hostname = domain
					end
					super hostname, port
				end

				def ssl_connect(socket, context, method, &block)
					socket.recv 1024
					socket.write "EHLO #{Socket.gethostbyname(Socket.gethostname).first}\r\n"
					features = socket.recv(1024).split "\r\n"
					starttls = features.find { |f| /250[- ]STARTTLS/ =~ f }
					raise TLSNotAvailableException unless starttls
					socket.write "STARTTLS\r\n"
					socket.recv 1024
					super
				end
			end
		end
	end
end

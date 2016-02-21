module CryptCheck
	module Tls
		module Smtp
			class Server < Tls::TcpServer
				attr_reader :domain

				def initialize(family, ip, port, hostname: nil, domain:)
					@domain = domain
					super family, ip, port, hostname: hostname
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

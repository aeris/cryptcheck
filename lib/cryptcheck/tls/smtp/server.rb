module CryptCheck
	module Tls
		module Smtp
			class Server < Tls::Server
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

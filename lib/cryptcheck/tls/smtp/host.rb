module CryptCheck
	module Tls
		module Smtp
			class Host < Tls::Host
				private

				def server(*args)
					Smtp::Server.new *args
				end
			end
		end
	end
end

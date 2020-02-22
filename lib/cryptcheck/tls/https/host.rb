module CryptCheck
	module Tls
		module Https
			class Host < CryptCheck::Host
				private

				def server(*args)
					Https::Server.new *args
				end
			end
		end
	end
end

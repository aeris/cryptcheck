module CryptCheck
	module Tls
		module Smtp
			class Host < CryptCheck::Host
				private

				def server(*args)
					Smtp::Server.new *args
				end
			end
		end
	end
end

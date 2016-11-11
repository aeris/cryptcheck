module CryptCheck
	module Tls
		module Https
			class Grade < Tls::Grade
				def all_success
					super + %i(hsts hsts_long)
				end
			end
		end
	end
end

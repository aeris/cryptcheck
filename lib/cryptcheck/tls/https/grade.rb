module CryptCheck
	module Tls
		module Https
			class Grade < Tls::Grade
				CHECKS = {
						good:    %i(hsts),
						perfect: %i(hsts_long)
				}

				def checks
					State.merge super, CHECKS
				end
			end
		end
	end
end

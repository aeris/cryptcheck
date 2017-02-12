module CryptCheck
	module Tls
		module Smtp
			class Grade < Tls::Grade
				CHECKS = {
				}

				def checks
					State.merge super, CHECKS
				end
			end
		end
	end
end

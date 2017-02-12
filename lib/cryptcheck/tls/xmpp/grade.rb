module CryptCheck
	module Tls
		module Xmpp
			class Grade < Tls::Grade
				CHECKS = {
						good: %i(required)
				}

				def checks
					State.merge super, CHECKS
				end
			end
		end
	end
end

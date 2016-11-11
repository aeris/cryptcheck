module CryptCheck
	module Tls
		module Xmpp
			class Grade < Tls::Grade
				def all_success
					super + %i(required)
				end
			end
		end
	end
end

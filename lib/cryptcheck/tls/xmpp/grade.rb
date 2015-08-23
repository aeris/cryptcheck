module CryptCheck
	module Tls
		module Xmpp
			class Grade < Tls::Grade
				def calculate_success
					super
					@success << :required if @server.required?
				end

				def all_success
					super + %i(required)
				end
			end
		end
	end
end

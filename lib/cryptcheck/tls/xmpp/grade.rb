module CryptCheck
	module Tls
		module Xmpp
			class Grade < Tls::Grade
				def checks
					super + [
							[:required, Proc.new { |s| s.required? }, :good],
					]
				end
			end
		end
	end
end

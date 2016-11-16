module CryptCheck
	module Tls
		module Https
			class Grade < Tls::Grade
				def checks
					super + [
						[:hsts, Proc.new { |s| s.hsts? }, :good],
						[:hsts_long, Proc.new { |s| s.hsts_long? }, :perfect],
					]
				end
			end
		end
	end
end

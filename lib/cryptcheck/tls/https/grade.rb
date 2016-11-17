module CryptCheck
	module Tls
		module Https
			class Grade < Tls::Grade
				def checks
					super + [
						[:hsts, Proc.new { |s| s.hsts? }, :good],
						[:hsts_long, Proc.new { |s| s.hsts_long? }, :perfect],

						#[:must_staple, Proc.new { |s| s.must_staple? }, :best],
					]
				end
			end
		end
	end
end

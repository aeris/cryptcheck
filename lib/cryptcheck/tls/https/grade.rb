# This module return the grade of hsts

module CryptCheck
	module Tls
		module Https
			class Grade < Tls::Grade
				private
				def success
					super
					@success << :hsts if @server.hsts?
					@success << :hsts_long if @server.hsts_long?
				end

				def all_success
					super + %i(hsts hsts_long)
				end
			end
		end
	end
end

require 'resolve'

class Resolv::DNS::Resource::IN::CAA < Resolv::DNS::Resource::IN::TXT
	TypeValue = 257
end

module CryptCheck
	module Tls
		module CAA
			def check_caa

			end
		end
	end
end

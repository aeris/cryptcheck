module CryptCheck
	module Tls
		module Xmpp
			class Host < Tls::Host
				attr_reader :domain

				def initialize(*args, domain: nil, type: :s2s)
					@domain, @type = domain, type
					super *args
					Logger.info { '' }
					Logger.info { self.required? ? 'Required'.colorize(:good) : 'Not required'.colorize(:warning) }
				end

				private

				def server(*args)
					Xmpp::Server.new *args, domain: @domain, type: @type
				end
			end
		end
	end
end

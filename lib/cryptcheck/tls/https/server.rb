require 'httparty'

module CryptCheck
	module Tls
		module Https
			class Server < Tls::TcpServer
				attr_reader :hsts

				def initialize(hostname, family, ip, port=443)
					super
					fetch_hsts
				end

				def fetch_hsts
					port = @port == 443 ? '' : ":#{@port}"

					begin
						response = ::HTTParty.head "https://#{@hostname}#{port}/",
												   {
														   follow_redirects: false,
														   verify:           false,
														   timeout:          SSL_TIMEOUT,
														   ssl_version:      self.supported_protocols.first,
														   ciphers:          'ALL:COMPLEMENTOFALL'
												   }
						if header = response.headers['strict-transport-security']
							name, value = header.split '='
							if name == 'max-age'
								@hsts = value.to_i
								Logger.info { "HSTS : #{@hsts.to_s.colorize hsts_long? ? :green : nil}" }
								return
							end
						end
					rescue
					end

					Logger.info { 'No HSTS'.colorize :yellow }
					@hsts = nil
				end

				def hsts?
					!@hsts.nil?
				end

				LONG_HSTS = 6*30*24*60*60
				def hsts_long?
					hsts? and @hsts >= LONG_HSTS
				end
			end
		end
	end
end

require 'httparty'

# This module open connection with httparty
# make a HEAD and extract the HSTS
# If HTSTS is present and >~ 6months
#
# @return: htsts || hsts_long

module CryptCheck
	module Tls
		module Https
			class Server < Tls::TcpServer
				attr_reader :hsts

				def initialize(hostname, port=443)
					super
					fetch_hsts
				end

				def fetch_hsts
					port = @port == 443 ? '' : ":#{@port}"

					begin
						response = ::HTTParty.head "https://#{@hostname}#{port}/", { follow_redirects: false, verify: false, timeout: SSL_TIMEOUT }
						if header = response.headers['strict-transport-security']
							name, value = header.split '='
							if name == 'max-age'
								@hsts = value.to_i
								Logger.info { "HSTS : #{@hsts.to_s.colorize hsts_long? ? :green : nil}" }
								return
							end
						end
					rescue ::Net::OpenTimeout
					end

					Logger.info { 'No HSTS'.colorize :yellow }
					@hsts = nil
				end

				def hsts?
					!@hsts.nil?
				end

				def hsts_long?
					hsts? and @hsts >= 6*30*24*60*60 # ~6months
				end
			end
		end
	end
end

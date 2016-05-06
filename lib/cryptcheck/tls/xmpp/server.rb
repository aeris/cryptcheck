require 'nokogiri'

module CryptCheck
	module Tls
		module Xmpp
			TLS_NAMESPACE = 'urn:ietf:params:xml:ns:xmpp-tls'

			class Server < Tls::TcpServer
				attr_reader :domain

				def initialize(hostname, family, ip, port=nil, domain: nil, type: :s2s)
					domain         ||= hostname
					@type, @domain = type, domain
					port           = case type
										 when :s2s
											 5269
										 when :c2s
											 5222
									 end unless port
					super hostname, family, ip, port
					Logger.info { '' }
					Logger.info { self.required? ? 'Required'.colorize(:green) : 'Not required'.colorize(:yellow) }
				end

				def ssl_connect(socket, context, method, &block)
					type = case @type
							   when :s2s then
								   'jabber:server'
							   when :c2s then
								   'jabber:client'
						   end
					socket.puts "<?xml version='1.0' ?><stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='#{type}' to='#{@domain}' version='1.0'>"
					response = ''
					loop do
						response += socket.recv 1024
						xml      = ::Nokogiri::XML response
						error    = xml.xpath '//stream:error'
						raise ConnectionError, error.first.child.to_s unless error.empty?
						unless xml.xpath('//stream:features').empty?
							response = xml
							break
						end
					end
					starttls = response.xpath '//tls:starttls', tls: TLS_NAMESPACE
					raise TLSNotAvailableException unless starttls
					@required = !starttls.xpath('//tls:required', tls: TLS_NAMESPACE).empty?
					socket.write "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls' />\r\n"
					response = ::Nokogiri::XML socket.recv 4096
					raise TLSNotAvailableException unless response.xpath '//tls:proceed', tls: TLS_NAMESPACE
					super
				end

				def required?
					@required
				end
			end
		end
	end
end

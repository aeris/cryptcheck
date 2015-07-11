require 'nokogiri'
require 'resolv'

module CryptCheck
	module Tls
		module Xmpp
			TLS_NAMESPACE = 'urn:ietf:params:xml:ns:xmpp-tls'
			RESOLVER = Resolv::DNS.new

			class Server < Tls::TcpServer
				attr_reader :domain

				def initialize(domain, type=:s2s, hostname: nil)
					@type, @domain = type, domain
					service, port = case type
								  when :s2s then ['_xmpp-server', 5269]
								  when :c2s then ['_xmpp-client', 5222]
							  end
					unless hostname
						srv = RESOLVER.getresources("#{service}._tcp.#{domain}", Resolv::DNS::Resource::IN::SRV).sort_by(&:priority).first
						if srv
							hostname, port = srv.target.to_s, srv.port
						else # DNS is not correctly set, guess config…
							hostname = domain
						end
					end
					super hostname, port
				end

				def ssl_connect(socket, context, method, &block)
					type = case @type
								 when :s2s then 'jabber:server'
								 when :c2s then 'jabber:client'
							 end
					socket.write "<?xml version='1.0' ?><stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='#{type}' to='#{@domain}' version='1.0'>"
					response = ''
					loop do
						response += socket.recv 1024
						xml = ::Nokogiri::XML response
						unless xml.xpath('//stream:features').empty?
							response = xml
							break
						end
					end
					starttls = response.xpath '//tls:starttls', tls: TLS_NAMESPACE
					raise TLSNotAvailableException unless starttls
					@required = !starttls.xpath('//tls:required', tls: TLS_NAMESPACE).nil?
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

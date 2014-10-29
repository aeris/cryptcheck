require 'httparty'
require 'nokogiri'

module SSLCheck
	module SSLLabs
		class Error < StandardError; end
		class WaitingError < Error; end
		class ServerError < Error; end
		class NoEncryptionError < Error; end

		class API
			include HTTParty
			#debug_output $stdout
			base_uri 'https://www.ssllabs.com/ssltest'

			attr_reader :hostname, :ip, :rank, :ssl, :tls, :bits, :rc4, :pfs, :hsts

			def initialize(hostname, debug: false)
				@debug = debug
				@hostname = hostname
				@ip = nil
				html = content hostname
				@rank = html.css('#rating div')[1].text.strip
				parse_configuration html
			end

			private
			def content(hostname, ip=nil)
				#puts "host: #{hostname}, ip: #{ip}"
				options = {query: {d: hostname}}
				options[:query][:s] = ip unless ip.nil?

				html = nil
				loop do
					response = self.class.get '/analyze.html', options
					raise ServerError, response.code unless response.success?
					html = Nokogiri::HTML response.body
					File.write File.join('html', hostname), html if @debug
					break if not resolving_domain? html
				end
				waiting? html

				html = resolve_multiple_servers html
				encrypted? html

				@hostname = html.at_css('.url').content.strip
				ip = html.at_css '.ip'
				unless ip.nil?
					@ip = ip.content.strip.gsub /[()]/, ''
				else
					@ip = ''
				end
				html
			end

			def waiting?(html)
				warning = html.at_css '#warningBox'
				raise WaitingError if not warning.nil? and warning.content.include? 'Please wait...'
			end

			def encrypted?(html)
				warning = html.at_css '#warningBox'
				raise NoEncryptionError if not warning.nil? and \
				 warning.content.include? 'Assessment failed: Unable to connect to server'
			end

			def resolving_domain?(html)
				warning = html.at_css('#warningBox')
				not warning.nil? and warning.content.strip == 'Please wait... (Resolving domain names)'
			end

			def resolve_multiple_servers(html)
				servers = html.at_css('#multiTable')
				return html if servers.nil?
				servers.css('tr').each do |server|
					td = server.css('td')[4]
					next if td.nil?
					rank = td.content.strip
					unless rank == '-'
						ip = server.at_css('.ip').content
						html = content hostname, ip
						waiting? html
						return html
					end
				end
				raise NoEncryptionError
			end

			def parse_configuration(html)
				configuration = html.css('.reportSection')[2]
				parse_protocols configuration
				parse_handshakes configuration
				parse_details configuration
			end

			def parse_protocols(configuration)
				protocols = configuration.css('.reportTable')[0].css('tr.tableRow')
				@tls = true
				@ssl = false
				protocols.each do |row|
					cells = row.css 'td'
					next unless cells.size >= 2
					name = cells[0].content.strip
					value = cells[1].content.strip
					case name
						when /^TLS 1.2/ then
							@tls = value == 'Yes'
						when /^SSL 2/ then
							@ssl |= value != 'No'
						when /^SSL 3/ then
							@ssl |= value != 'No'
					end
				end
			end

			def parse_handshakes(configuration)
				@bits = nil
				handshakes = configuration.css('.reportTable')[2].css('td.tableRight')
				handshakes.each do |cell|
					value = cell.content.strip
					begin
						i = Integer value
						@bits = @bits.nil? ? i : [@bits, i].min
					rescue
					end
				end
			end

			def parse_details(configuration)
				@rc4 = @pfs = @hsts = nil
				details = configuration.css('.reportTable')[3].css('tr.tableRow')
				details.each do |row|
					cells = row.css 'td'
					name = cells[0].content.strip
					value = cells[1].content.strip
					case name
						when 'RC4' then
							@rc4 = value != 'No'
						when 'Forward Secrecy' then
							@pfs = value == 'Yes (with most browsers)   ROBUST (more info)'
						when 'Strict Transport Security (HSTS)' then
							@hsts = value.start_with? 'Yes'
					end
				end
			end
		end
	end
end

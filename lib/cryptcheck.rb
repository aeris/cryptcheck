require 'colorize'
require 'ipaddr'
require 'timeout'
require 'yaml'
require 'cryptcheck/tls/fixture'

module CryptCheck
	MAX_ANALYSIS_DURATION = 600
	PARALLEL_ANALYSIS     = 10

	autoload :Logger, 'cryptcheck/logger'
	autoload :Tls, 'cryptcheck/tls'
	module Tls
		autoload :Cipher, 'cryptcheck/tls/cipher'
		autoload :Server, 'cryptcheck/tls/server'
		autoload :TcpServer, 'cryptcheck/tls/server'
		autoload :UdpServer, 'cryptcheck/tls/server'
		autoload :TlsNotSupportedServer, 'cryptcheck/tls/server'
		autoload :Grade, 'cryptcheck/tls/grade'
		autoload :TlsNotSupportedGrade, 'cryptcheck/tls/grade'

		autoload :Https, 'cryptcheck/tls/https'
		module Https
			autoload :Server, 'cryptcheck/tls/https/server'
			autoload :Grade, 'cryptcheck/tls/https/grade'
		end

		autoload :Xmpp, 'cryptcheck/tls/xmpp'
		module Xmpp
			autoload :Server, 'cryptcheck/tls/xmpp/server'
			autoload :Grade, 'cryptcheck/tls/xmpp/grade'
		end

		autoload :Smtp, 'cryptcheck/tls/smtp'
		module Smtp
			autoload :Server, 'cryptcheck/tls/smtp/server'
			autoload :Grade, 'cryptcheck/tls/smtp/grade'
		end
	end

	autoload :Ssh, 'cryptcheck/ssh'
	module Ssh
		autoload :Packet, 'cryptcheck/ssh/packet'
		autoload :Server, 'cryptcheck/ssh/server'
		autoload :SshNotSupportedServer, 'cryptcheck/ssh/server'
		autoload :Grade, 'cryptcheck/ssh/grade'
	end

	private
	def self.addresses(host)
		begin
			ip = IPAddr.new host
			[[ip.family, ip.to_s, nil]]
		rescue IPAddr::InvalidAddressError
			begin
				::Addrinfo.getaddrinfo(host, nil, nil, :STREAM)
						.collect { |a| [a.afamily, a.ip_address, host] }
			rescue ::SocketError => e
				Logger.error { "Unable to resolv #{host} : #{e}" }
				[]
			end
		end
	end

	def self.analyze_addresses(host, addresses, port, on_error = TLS_NOT_AVAILABLE, &block)
		begin
			::Timeout::timeout MAX_ANALYSIS_DURATION do
				addresses.each { |family, ip, host| return block.call family, ip, host }
			end
		rescue ::Exception => e
			Logger.error e
		end
		on_error.call host, port
	end

	def self.analyze(host, port, on_error = Tls::TLS_NOT_AVAILABLE, &block)
		analyze_addresses host, addresses(host), port, on_error, &block
	end

	def self.analyze_hosts(hosts, template, output, groups: nil, &block)
		results   = {}
		semaphore = ::Mutex.new
		::Parallel.each hosts, progress: 'Analysing', in_threads: PARALLEL_ANALYSIS, finish: lambda { |item, _, _| puts item[1] } do |description, host|
		#hosts.each do |description, host|
			result = block.call host.strip
			semaphore.synchronize do
				if results.include? description
					results[description] << result
				else
					results[description] = [result]
				end
			end
		end

		results = ::Hash[groups.collect { |g| [g, results[g]] }] if groups

		results.each do |d, _|
			results[d].sort! do |a, b|
				cmp = score(a) <=> score(b)
				if cmp == 0
					cmp = b.score <=> a.score
					if cmp == 0
						cmp = a.server.hostname <=> b.server.hostname
					end
				end
				cmp
			end
		end

		::File.write output, ::ERB.new(::File.read template).result(binding)
	end

	def self.analyze_file(input, template, output, &block)
		config = ::YAML.load_file input
		hosts  = []
		groups = []

		config.each do |c|
			d, hs = c['description'], c['hostnames']
			groups << d
			hs.each { |host| hosts << [d, host] }
		end

		self.analyze_hosts hosts, template, output, groups: groups, &block
	end

	private
	SCORES = %w(A+ A A- B C D E F T M X)

	def self.score(a)
		SCORES.index a.grade
	end
end

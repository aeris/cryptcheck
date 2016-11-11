require 'colorize'
require 'ipaddr'
require 'timeout'
require 'yaml'
require 'cryptcheck/tls/fixture'

module CryptCheck
	MAX_ANALYSIS_DURATION = 120
	PARALLEL_ANALYSIS     = 10

	class AnalysisFailure
		attr_reader :error

		def initialize(error)
			@error = error
		end

		def to_s
			@error.to_s
		end
	end

	class NoTLSAvailableServer
		attr_reader :server
		def initialize(server)
			@server = OpenStruct.new hostname: server
		end

		def grade
			'X'
		end

		def score
			0
		end
	end

	autoload :Logger, 'cryptcheck/logger'
	autoload :Tls, 'cryptcheck/tls'
	module Tls
		autoload :Cipher, 'cryptcheck/tls/cipher'
		autoload :Server, 'cryptcheck/tls/server'
		autoload :TcpServer, 'cryptcheck/tls/server'
		autoload :UdpServer, 'cryptcheck/tls/server'
		autoload :Grade, 'cryptcheck/tls/grade'

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
			return [[ip.family, ip.to_s, nil]]
		rescue IPAddr::InvalidAddressError
		end
		::Addrinfo.getaddrinfo(host, nil, nil, :STREAM)
				.collect { |a| [a.afamily, a.ip_address, host] }
	end

	def self.analyze_addresses(host, addresses, port, server, grade, *args, **kargs)
		first = true
		addresses.collect do |family, ip|
			first ? (first = false) : Logger.info { '' }
			key = [host, ip, port]
			a   = [host, family, ip, port, *args]
			begin
				::Timeout::timeout MAX_ANALYSIS_DURATION do
					s = if kargs.empty?
							server.new *a
						else
							server.new *a, **kargs
						end
					if grade
						g = grade.new s
						Logger.info { '' }
						g.display
						[key, g]
					else
						[key, s]
					end
				end
			rescue => e
				e = "Too long analysis (max #{MAX_ANALYSIS_DURATION.humanize})" if e.message == 'execution expired'
				Logger.error e
				[key, AnalysisFailure.new(e)]
			end
		end.to_h
	end

	def self.analyze(host, port, server, grade, *args, **kargs)
		addresses = begin
			addresses host
		rescue ::SocketError => e
			Logger::error e
			key = [host, nil, port]
			error = AnalysisFailure.new "Unable to resolve #{host}"
			return { key => error }
		end
		analyze_addresses host, addresses, port, server, grade, *args, **kargs
	end

	def self.analyze_hosts(hosts, template, output, groups: nil, &block)
		results   = {}
		semaphore = ::Mutex.new
		::Parallel.each hosts, progress: 'Analysing', in_threads: PARALLEL_ANALYSIS, finish: lambda { |item, _, _| puts item[1] } do |description, host|
			#hosts.each do |description, host|
			result = block.call host.strip
			result = result.values.first
			result = NoTLSAvailableServer.new(host) if result.is_a? AnalysisFailure
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

require 'erb'
require 'logging'
require 'parallel'
require 'thread'
require 'yaml'

module SSLCheck
	module SSLLabs
		autoload :API, 'sslcheck/ssllabs/api'
	end
	autoload :Server, 'sslcheck/server'
	autoload :Grade, 'sslcheck/grade'

	PARALLEL_ANALYSIS = 20
	SYN_TIMEOUT = 600
	@@log = Logging.logger[SSLCheck]

	def self.grade(hostname, port=443)
		timeout SYN_TIMEOUT do
			Grade.new Server.new hostname, port
		end
	rescue Exception => e
		@@log.error { "Error during #{hostname}:#{port} analysis : #{e}" }
		NoSslTlsGrade.new NoSslTlsServer.new hostname, port
	end

	def self.analyze(hosts, output, groups = nil)
		results = {}
		semaphore = Mutex.new
		Parallel.each hosts, progress: 'Analysing', in_threads: PARALLEL_ANALYSIS,
			finish: lambda { |item, _, _| puts item[1] } do |description, host|
			result = SSLCheck.grade host.strip
			semaphore.synchronize do
				if results.include? description
					results[description] << result
				else
					results[description] = [result]
				end
			end
		end

		results = Hash[groups.collect { |g| [g, results[g]] }] if groups

		results.each do |d, _|
			results[d].sort! do |a, b|
				cmp = score(a) <=> score(b)
				if cmp == 0
					cmp = a.score <=> b.score
					if cmp == 0
						cmp = a.server.hostname <=> b.server.hostname
					end
				end
				cmp
			end
		end

		File.write output, ERB.new(File.read('output/sslcheck.erb')).result(binding)
	end

	def self.analyze_from_file(file, output)
		config = YAML.load_file file
		hosts = []
		groups = []
		config.each do |c|
			d, hs = c['description'], c['hostnames']
			groups << d
			hs.each { |host| hosts << [d, host] }
		end
		self.analyze hosts, output, groups
	end

	private
	SCORES = %w(A+ A A- B C D E F T M X)
	def self.score(a)
		SCORES.index a.grade
	end
end

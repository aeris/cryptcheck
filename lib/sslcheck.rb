require 'erb'
require 'logging'
require 'parallel'
require 'thread'

module SSLCheck
	module SSLLabs
		autoload :API, 'sslcheck/ssllabs/api'
	end
	autoload :Server, 'sslcheck/server'
	autoload :Grade, 'sslcheck/grade'

	@@log = Logging.logger[SSLCheck]

	def self.grade(hostname, port=443)
		timeout 600 do
			Grade.new Server.new hostname, port
		end
	rescue Exception => e
		@@log.error { "Error during #{hostname}:#{port} analysis : #{e}" }
		NoSslTlsGrade.new NoSslTlsServer.new hostname, port
	end

	def self.analyze(hosts, output)
		results = {}
		semaphore = Mutex.new
		Parallel.each hosts, progress: 'Testing', in_threads: 10 do |description, host|
			result = SSLCheck.grade host.strip
			semaphore.synchronize do
				if results.include? description
					results[description] << result
				else
					results[description] = [result]
				end
			end
		end

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

		File.write "output/#{output}.html", ERB.new(File.read('output/sslcheck.erb')).result(binding)
	end

	private
	SCORES = %w(A+ A A- B C D E F T M X)
	def self.score(a)
		SCORES.index a.grade
	end
end

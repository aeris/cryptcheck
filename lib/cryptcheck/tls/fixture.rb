require 'openssl'

class String
	alias :colorize_old :colorize

	COLORS = {
			critical: { color: :white, background: :red },
			error:    :red,
			warning:  :light_red,
			good:     :green,
			perfect:  :blue,
			best:     :magenta,
			unknown:  { background: :black }
	}

	def colorize(state)
		color = COLORS[state] || state
		self.colorize_old color
	end
end

class Exception
	BACKTRACE_REGEXP = /^(.*):(\d+):in `(.*)'$/

	def colorize
		$stderr.puts self.message.colorize(:red)
		self.backtrace.each do |line|
			line = BACKTRACE_REGEXP.match line
			line = '%s:%s:in `%s\'' % [
					line[1].colorize(:yellow),
					line[2].colorize(:blue),
					line[3].colorize(:magenta)
			]
			$stderr.puts line
		end
	end
end

class Integer
	def humanize
		secs = self
		[[60, :second],
		 [60, :minute],
		 [24, :hour],
		 [30, :day],
		 [12, :month]].map do |count, name|
			if secs > 0
				secs, n = secs.divmod count
				n       = n.to_i
				n > 0 ? "#{n} #{name}#{n > 1 ? 's' : ''}" : nil
			end
		end.compact.reverse.join ' '
	end
end

class ::OpenSSL::PKey::EC
	def type
		:ecc
	end

	def size
		self.group.degree
	end

	def curve
		self.group.curve_name
	end

	def to_s
		"ECC #{self.size} bits"
	end

	def status
		case self.size
			when 0...160
				:critical
			when 160...192
				:error
			when 192...256
				:warning
			when 256...364
			else
				:good
		end
	end
end

class ::OpenSSL::PKey::RSA
	def type
		:rsa
	end

	def size
		self.n.num_bits
	end

	def to_s
		"RSA #{self.size} bits"
	end

	def status
		case self.size
			when 0...1024
				:critical
			when 1024...2048
				:error
			when 2048...4096
			else
				:good
		end
	end
end

class ::OpenSSL::PKey::DSA
	def type
		:dsa
	end

	def size
		self.p.num_bits
	end

	def to_s
		"DSA #{self.size} bits"
	end

	def status
		return :critical
	end
end

class ::OpenSSL::PKey::DH
	def type
		:dh
	end

	def size
		self.p.num_bits
	end

	def to_s
		"DH #{self.size} bits"
	end

	def status
		case self.size
			when 0...1024
				:critical
			when 1024...2048
				:error
			when 2048...4096
			else
				:good
		end
	end
end

class ::OpenSSL::X509::Store
	def add_chains(chains)
		chains = [chains] unless chains.is_a? Enumerable
		chains.each do |chain|
			case chain
				when ::OpenSSL::X509::Certificate
					self.add_cert chain
				else
					if File.directory?(chain)
						Dir.entries(chain)
								.collect { |e| File.join chain, e }
								.select { |e| File.file? e }
								.each { |f| self.add_file f }
					else
						self.add_file chain
					end
			end
		end
	end
end

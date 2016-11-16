require 'openssl'

class String
	alias :colorize_old :colorize

	COLORS = {
			critical: { color: :white, background: :red },
			error: :red,
			warning: :light_red,
			good: :green,
			perfect: :blue,
			best: :magenta,
			unknown: { background: :black }
	}

	def colorize(state)
		self.colorize_old COLORS[state]
	end
end

class Integer
	def humanize
		secs = self
		[[60, :second], [60, :minute], [24, :hour], [30, :day], [12, :month]].map { |count, name|
			if secs > 0
				secs, n = secs.divmod count
				n = n.to_i
				n > 0 ? "#{n} #{name}#{n > 1 ? 's' : ''}" : nil
			end
		}.compact.reverse.join(' ')
	end
end

class ::OpenSSL::PKey::EC
	def type
		:ecc
	end

	def size
		self.group.degree
	end

	def to_s
		"ECC #{self.size} bits"
	end

	def status
		case self.size
			when 0...160 then :critical
			when 160...192 then :error
			when 192...256 then :warning
			when 384...::Float::INFINITY then :good
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
			when 0...1024 then :critical
			when 1024...2048 then :error
			when 4096...::Float::INFINITY then :good
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
			when 0...1024 then :critical
			when 1024...2048 then :error
			when 4096...::Float::INFINITY then :good
		end
	end
end

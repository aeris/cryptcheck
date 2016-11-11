require 'openssl'

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
			when 0...160 then :error
			when 160...256 then :warning
			when 384...::Float::INFINITY then :success
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
			when 0...1024 then :error
			when 1024...2048 then :warning
			when 4096...::Float::INFINITY then :success
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
		return :error
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
			when 0...1024 then :error
			when 1024...2048 then :warning
			when 4096...::Float::INFINITY then :success
		end
	end
end

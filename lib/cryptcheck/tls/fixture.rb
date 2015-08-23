require 'openssl'

class ::OpenSSL::PKey::EC
	def type
		:ecc
	end

	def size
		self.group.degree
	end

	def rsa_equivalent_size
		case self.size
			when 160 then 1024
			when 224 then 2048
			when 256 then 3072
			when 384 then 7680
			when 521 then 15360
			when 571 then 21000
		end
	end

	def to_s
		"ECC #{self.size} bits"
	end
end

class ::OpenSSL::PKey::RSA
	def type
		:rsa
	end

	def size
		self.n.num_bits
	end

	def rsa_equivalent_size
		self.size
	end

	def to_s
		"RSA #{self.size} bits"
	end
end

class ::OpenSSL::PKey::DSA
	def type
		:dsa
	end

	def size
		self.p.num_bits
	end

	def rsa_equivalent_size
		self.size
	end

	def to_s
		"DSA #{self.size} bits"
	end
end

class ::OpenSSL::PKey::DH
	def type
		:dh
	end

	def size
		self.p.num_bits
	end

	def rsa_equivalent_size
		self.size
	end

	def to_s
		"DH #{self.size} bits"
	end
end

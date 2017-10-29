require 'openssl'

class ::OpenSSL::PKey::PKey
	def fingerprint
		::OpenSSL::Digest::SHA256.hexdigest self.to_der
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

	def to_h
		{ type: :ecc, curve: self.curve, size: self.size, fingerprint: self.fingerprint, states: self.states }
	end

	protected
	include ::CryptCheck::State

	CHECKS = [
			[:ecc, %i(critical error warning), -> (s) do
				case s.size
				when 0...160
					:critical
				when 160...192
					:error
				when 192...256
					:warning
				else
					false
				end
			end]
	].freeze

	def available_checks
		CHECKS
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

	def to_h
		{ type: :rsa, size: self.size, fingerprint: self.fingerprint, states: self.states }
	end

	protected
	include ::CryptCheck::State

	CHECKS = [
			[:rsa, %i(critical error), ->(s) do
				case s.size
				when 0...1024
					:critical
				when 1024...2048
					:error
				else
					false
				end
			end]
	].freeze

	def available_checks
		CHECKS
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

	def to_h
		{ type: :dsa, size: self.size, fingerprint: self.fingerprint, states: self.states }
	end

	include ::CryptCheck::State

	CHECKS = [
			[:dsa, :critical, -> (_) { true }]
	].freeze

	protected
	def available_checks
		CHECKS
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

	def to_h
		{ size: self.size, fingerprint: self.fingerprint, states: self.states }
	end

	protected
	include ::CryptCheck::State

	CHECKS = [
			[:dh, %i(critical error), -> (s) do
				case s.size
				when 0...1024
					:critical
				when 1024...2048
					:error
				else
					false
				end
			end]
	].freeze

	protected
	def available_checks
		CHECKS
	end
end

class ::OpenSSL::X509::Certificate
	def fingerprint
		::OpenSSL::Digest::SHA256.hexdigest self.to_der
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

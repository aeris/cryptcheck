module CryptCheck
	module Tls
		class Curve
			attr_reader :name

			def initialize(name)
				@name = name
			end

			# SUPPORTED = %i(sect163k1 sect163r1 sect163r2 sect193r1
			# 	sect193r2 sect233k1 sect233r1 sect239k1 sect283k1 sect283r1
			# 	sect409k1 sect409r1 sect571k1 sect571r1 secp160k1 secp160r1
			# 	secp160r2 secp192k1 secp192r1 secp224k1 secp224r1 secp256k1
			# 	secp256r1 secp384r1 secp521r1
			# 	prime256v1
			# 	brainpoolP256r1 brainpoolP384r1 brainpoolP512r1)
			SUPPORTED = %i(secp256k1 sect283k1 sect283r1 secp384r1
				sect409k1 sect409r1 secp521r1 sect571k1 sect571r1
				prime192v1 prime256v1
				brainpoolP256r1 brainpoolP384r1 brainpoolP512r1).collect { |c| self.new c }.freeze

			extend Enumerable

			def self.each(&block)
				SUPPORTED.each &block
			end

			def to_s
				@name
			end

			def ==(other)
				case other
					when String
						@name == other.to_sym
					when Symbol
						@name == other
					else
						@name == other.name
				end
			end

			protected
			include State

			CHECKS = [].freeze

			protected
			def available_checks
				CHECKS
			end
		end
	end
end

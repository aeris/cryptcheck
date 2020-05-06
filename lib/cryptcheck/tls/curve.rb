module CryptCheck
	module Tls
		class Curve
			attr_reader :name

			def initialize(name)
				name  = name.to_sym if name.is_a? String
				@name = name
			end

			SUPPORTED = %i(secp256k1 sect283k1 sect283r1 secp384r1
				sect409k1 sect409r1 secp521r1 sect571k1 sect571r1
				prime192v1 prime256v1
				brainpoolP256r1 brainpoolP384r1 brainpoolP512r1 x25519).collect { |c| self.new c }.freeze

			extend Enumerable

			def self.each(&block)
				SUPPORTED.each &block
			end

			def to_s
				@name
			end

			def to_h
				{ name: @name, states: self.states }
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

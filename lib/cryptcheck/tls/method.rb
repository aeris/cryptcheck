module CryptCheck
	module Tls
		class Method
			extend Enumerable

			def self.each(&block)
				SUPPORTED.each &block
			end

			attr_reader :name

			def initialize(name)
				@name = name
			end

			EXISTING  = %i(TLSv1_2 TLSv1_1 TLSv1 SSLv3 SSLv2).freeze
			SUPPORTED = (EXISTING & ::OpenSSL::SSL::SSLContext::METHODS).collect { |m| self.new m }.freeze

			def to_s
				colors = case @name
							 when *%i(SSLv3 SSLv2)
								 :critical
							 when :TLSv1_2
								 :good
						 end
				@name.to_s.colorize colors
			end

			def <=>(other)
				EXISTING.find_index(@name) <=> EXISTING.find_index(other.name)
			end
		end
	end
end

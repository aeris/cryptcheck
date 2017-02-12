module CryptCheck
	class Logger
		LEVELS  = %i(trace debug info warning error fatal none)
		@@level = :info

		def self.level=(level)
			@@level = level.to_sym
		end

		def self.log(level, string=nil, output: $stdout, &block)
			return unless enabled? level
			output.puts(string ? string : block.call)
		end

		if Object.respond_to? :ai
			def self.ap(name, object)
				self.debug { "#{name} : #{object.ai}" }
			end
		else
			def self.ap(name, object)
				self.debug { "#{name} : #{object}" }
			end
		end

		LEVELS.each do |level|
			class_eval <<-RUBY_EVAL, __FILE__, __LINE__ + 1
				def self.#{level}(string=nil, output: $stdout, &block)
					self.log :#{level}, string, output: output, &block
				end
			RUBY_EVAL
		end

		private
		def self.enabled?(level)
			LEVELS.index(level) >= LEVELS.index(@@level)
		end
	end
end

module CryptCheck
	class Status
		LEVELS   = %i(best perfect good warning error critical).freeze
		PROBLEMS = %i(warning error critical).freeze

		extend Enumerable

		def self.each(&block)
			LEVELS.each &block
		end

		def self.empty
			self.collect { |s| [s, []] }.to_h
		end

		def self.status(statuses)
			statuses = self.convert statuses
			self.min LEVELS, statuses
		end

		class << self
			alias_method :'[]', :status
		end

		def self.problem(statuses)
			statuses = self.convert statuses
			self.min PROBLEMS, statuses
		end

		def self.sort(statuses)
			statuses.sort { |a, b| self.compare a, b }
		end

		def self.compare(a, b)
			LEVELS.find_index(a.status) <=> LEVELS.find_index(b.status)
		end

		private
		def self.convert(statuses)
			statuses = [statuses] unless statuses.respond_to? :first
			first    = statuses.first
			statuses = statuses.collect &:status if first.respond_to? :status
			statuses
		end

		def self.min(levels, statuses)
			return nil if statuses.empty?
			(levels & statuses).last
		end
	end
end

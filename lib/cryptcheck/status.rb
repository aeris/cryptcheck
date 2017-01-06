module CryptCheck
	module Status
		LEVELS = %i(critical error warning good perfect best).freeze
		PROBLEMS = %i(critical error warning).freeze

		extend Enumerable
		def self.each(&block)
			LEVELS.each &block
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

		private
		def self.convert(statuses)
			statuses = [ statuses ] unless statuses.respond_to? :first
			first = statuses.first
			statuses = statuses.collect &:status if first.respond_to? :status
			statuses
		end

		def self.min(levels, statuses)
			return nil if statuses.empty?
			(levels & statuses).first
		end
	end
end

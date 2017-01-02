module CryptCheck
	module Status
		LEVELS = %i(critical error warning good perfect best).freeze
		PROBLEMS = %i(critical error warning).freeze

		def self.status(statuses)
			statuses = self.collect statuses
			self.select LEVELS, statuses
		end

		def self.problem(statuses)
			statuses = self.collect statuses
			self.select PROBLEMS, statuses
		end

		private
		def self.collect(statuses)
			first = statuses.first
			statuses = statuses.collect &:status if first.respond_to? :status
			statuses
		end

		def self.select(levels, statuses)
			return nil if statuses.empty?
			(levels & statuses).first
		end
	end
end

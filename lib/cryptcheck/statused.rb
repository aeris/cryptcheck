module CryptCheck
	module Statused
		def status
			@status ||= calculate_status
		end

		private
		def merge(statuses)
			Status.collect do |s|
				status = statuses.collect { |ss| ss[s] }
				status = status.inject &:+
				[s, status.uniq]
			end.to_h
		end

		def checks
			[]
		end

		def children
			[]
		end

		def perform_check(check)
			name, check, level = check
			result             = check.call self
			return nil unless result
			level ||= result
			[level, name]
		end

		def personal_status
			states = Status.empty
			checks.each do |check|
				level, name = perform_check check
				next unless level
				states[level] << name
			end
			states
		end

		def calculate_status
			children_statuses = children.collect(&:status)
			statuses = [personal_status] + children_statuses
			merge statuses
		end
	end
end

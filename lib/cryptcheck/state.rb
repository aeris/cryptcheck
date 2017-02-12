module CryptCheck
	module State
		def states
			@status ||= calculate_states
		end

		def status
			State.status self.states.reject { |_, v| v.empty? }.keys
		end

		LEVELS   = %i(best perfect good warning error critical).freeze
		PROBLEMS = %i(warning error critical).freeze

		extend Enumerable

		def self.each(&block)
			LEVELS.each &block
		end

		def self.empty
			self.collect { |s| [s, []] }.to_h
		end

		def self.status(states)
			states = self.convert states
			self.min LEVELS, states
		end

		class << self
			alias_method :'[]', :status
		end

		def self.problem(states)
			states = self.convert states
			self.min PROBLEMS, states
		end

		def self.sort(states)
			states.sort { |a, b| self.compare a, b }
		end

		def self.compare(a, b)
			LEVELS.find_index(a.status) <=> LEVELS.find_index(b.status)
		end

		def performed_checks
			self.states # Force internal resolution
			@performed_checks
		end

		private
		def self.convert(status)
			status = [status] unless status.respond_to? :first
			first  = status.first
			status = status.collect &:status if first.respond_to? :status
			status
		end

		def self.min(levels, states)
			return nil if states.empty?
			(levels & states).last
		end

		def self.merge(*states)
			State.collect do |s|
				state = states.collect { |ss| ss.fetch s, [] }
								.inject(&:+).uniq
				[s, state]
			end.to_h
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

		def personal_states
			states           = State.empty
			performed_checks = checks
			performed_checks.each do |check|
				level, name = perform_check check
				next unless level
				states[level] << name
			end

			performed_checks  = [
					performed_checks
							.collect { |n, _, l| [l, n] }
							.group_by(&:first)
							.map { |k, v| [k, v.collect(&:last)] }.to_h
			] + children.collect(&:performed_checks)
			@performed_checks = State.merge *performed_checks

			states
		end

		def calculate_states
			children_states = children.collect(&:states)
			states          = [personal_states] + children_states
			State.merge *states
		end
	end
end

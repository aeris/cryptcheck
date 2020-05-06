module CryptCheck
	module State
		def states
			# Remove duplicated test for each level
			@states ||= State.empty.merge(self.checks.group_by { |c| c[1] }.collect do |level, checks|
				states = checks.group_by(&:first).collect do |name, checks|
					states = checks.collect &:last
					# true > false > nil
					state  = if states.include? true
								 true
							 elsif states.include? false
								 false
							 else
								 nil
							 end
					[name, state]
				end.to_h
				[level, states]
			end.to_h)
		end

		def status
			@status ||= State.status self.checks.select { |c| c.last == true }.collect { |c| c[1] }
		end

		BADS   = %i(critical error warning).freeze
		GOODS  = %i(good great best).freeze
		LEVELS = (BADS + GOODS).freeze

		def self.good?(level)
			GOODS.include? level
		end

		def self.bad?(level)
			BADS.include? level
		end

		def self.good_or_bad(level)
			if self.good?(level)
				:good
			else
				:bad
			end
		end

		def self.state(states, level)
			state =states[level].values.uniq
			case State.good_or_bad(level)
				when :bad
					if state.include? true
						true
					else
						false
					end
				when :good
					if state.include? false
						if state.include? true
							:some
						else
							false
						end
					else
						:all
					end
			end
		end

		extend Enumerable

		def self.each(&block)
			LEVELS.each &block
		end

		def self.empty
			self.collect { |s| [s, {}] }.to_h
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
			self.min BADS, states
		end

		def self.sort(states)
			states.sort { |a, b| self.compare a, b }
		end

		def self.compare(a, b)
			a = LEVELS.find_index(a.status) || (LEVELS.size - 1) / 2.0
			b = LEVELS.find_index(b.status) || (LEVELS.size - 1) / 2.0
			b <=> a
		end

		def checks
			@checks ||= self.available_checks.collect { |c| perform_check c }.flatten(1) + children.collect(&:checks).flatten(1)
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
			(levels & states).first
		end

		def self.max(levels, states)
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
			name, levels, check = check
			result              = check.call self
			case levels
				when Symbol # Expected result is true/false/nil
					return [[name, levels, result]]
				else # Expected result is the best/worst case
					# N/A, so return all levels as N/A
					return levels.collect { |l| [name, l, nil] } if result.nil?

					checks = []
					if BADS.include? result
						checks += (GOODS & levels).collect { |l| [name, l, false] }
						index  = BADS.index result
						checks += (BADS & levels).collect { |l| [name, l, BADS.index(l) >= index] }
					else
						checks += (BADS & levels).collect { |l| [name, l, false] }
						index  = GOODS.index result
						checks += (GOODS & levels).collect { |l| [name, l, GOODS.index(l) <= index] }
					end
					return checks
			end
		end
	end
end

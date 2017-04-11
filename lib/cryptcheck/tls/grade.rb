module CryptCheck
	module Tls
		module Grade
			def grade
				@grade ||= calculate_grade
			end

			GRADES = %i(A+ A B+ B C+ C D E F G V T X)
			GRADE_STATUS = {
					V: :critical,
					T: :critical,

					G: :critical,
					F: :error,
					E: :warning,
					D: nil,
					C: :good,
					:'C+' => :good,
					B: :great,
					:'B+' => :great,
					A: :best,
					:'A+' => :best
			}
			def grade_status
				GRADE_STATUS.fetch self.grade, :unknown
			end

			private
			def calculate_grade
				return :V unless self.valid?
				return :T unless self.trusted?

				states = self.states

				{ critical: :G, error: :F, warning: :E }.each do |type, grade|
					return grade if states[type].any? { |s| s == true }
				end

				{good: %i(D C), great: %i(C B), best: %i(B A)}.each do |type, scores|
					state = states[type]
					return scores.first if state.all? { |s| s != false }
					if state.any? { |s| s == false }
						Logger.info { "Missing #{type} : #{states[type].select { |s| s == false }.collect &:key}" }
						return scores.last
					end
				end

				:'A+'
			end
		end
	end
end

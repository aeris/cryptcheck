module CryptCheck
	module Grade
		def grade
			@grade ||= calculate_grade
		end

		GRADES        = %i(A+ A B+ B C+ C D E F G V T X)
		GRADE_STATUS  = {
				:'A+' => :best,
				A:    :best,
				:'B+' => :great,
				B:    :great,
				:'C+' => :good,
				C:    :good,
				D:    nil,
				E:    :warning,
				F:    :error,
				G:    :critical,

				V:    :critical,
				T:    :critical,
				X:    :critical
		}
		STATUS_GRADES = {
				critical: :G,
				error:    :F,
				warning:  :E,
				default:  :D,
				good:     :C,
				great:    :B,
				best:     :A
		}

		def grade_status
			GRADE_STATUS.fetch self.grade, :unknown
		end

		private
		def calculate_grade
			return :V unless self.valid?
			return :T unless self.trusted?

			states = self.states
			states = State.collect { |s| [s, State.state(states, s)] }.to_h

			State::BADS.each do |s|
				return STATUS_GRADES[s] if states[s]
			end

			grade = STATUS_GRADES[:default]
			State::GOODS.each do |s|
				state = states[s]
				return grade if state == false
				grade = STATUS_GRADES[s]
				return grade if state == :some
				grade = "#{grade}+".to_sym
			end
			grade
		end
	end
end

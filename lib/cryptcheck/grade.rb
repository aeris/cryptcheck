module CryptCheck
  module Grade
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

    def grade
      @grade ||= calculate_grade
    end

    def grade_status
      GRADE_STATUS.fetch self.grade, :unknown
    end
  end
end

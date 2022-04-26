module CryptCheck
  module Grade
    GRADES        = %i(A+ A B+ B C+ C D E F G V T X).freeze
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
    }.freeze
    STATUS_GRADES = {
      critical: :G,
      error:    :F,
      warning:  :E,
      default:  :D,
      good:     :C,
      great:    :B,
      best:     :A
    }.freeze

    def grade
      @grade ||= calculate_grade
    end

    def grade_status
      GRADE_STATUS.fetch self.grade, :unknown
    end

    def self.compare(a, b)
      GRADES.index(a.to_sym) <=> GRADES.index(b.to_sym)
    end

    def self.sort(grades)
      grades.sort &self.method(:compare)
    end

    def self.better(grades)
      self.sort(grades).first
    end

    def self.worst(grades)
      self.sort(grades).last
    end
  end
end

module CryptCheck
  module Tls
    module Grade
      include CryptCheck::Grade

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
end

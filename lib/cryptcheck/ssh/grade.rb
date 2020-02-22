module CryptCheck
  module Ssh
    module Grade
      include CryptCheck::Grade

      def states
        {}
      end

      private

      def calculate_grade
        :'-'
      end
    end
  end
end

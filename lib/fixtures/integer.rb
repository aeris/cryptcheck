module Fixture
  module Integer
    def humanize
      secs = self
      [[60, :second],
       [60, :minute],
       [24, :hour],
       [30, :day],
       [12, :month]].map do |count, name|
        if secs > 0
          secs, n = secs.divmod count
          n       = n.to_i
          n > 0 ? "#{n} #{name}#{n > 1 ? 's' : ''}" : nil
        end
      end.compact.reverse.join ' '
    end
  end
end

::Integer.include Fixture::Integer

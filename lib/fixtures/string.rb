module Fixture
  module String
    COLORS = {
      critical: { color: :white, background: :red },
      error:    :red,
      warning:  :light_red,
      good:     :green,
      great:    :blue,
      best:     :magenta,
      unknown:  { background: :black }
    }

    def colorize(state)
      color = COLORS[state] || state
      super color
    end
  end
end

String.prepend Fixture::String

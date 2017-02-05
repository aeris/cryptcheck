class String
	alias :colorize_old :colorize

	COLORS = {
			critical: { color: :white, background: :red },
			error:    :red,
			warning:  :light_red,
			good:     :green,
			perfect:  :blue,
			best:     :magenta,
			unknown:  { background: :black }
	}

	def colorize(state)
		color = COLORS[state] || state
		self.colorize_old color
	end
end

class Exception
	BACKTRACE_REGEXP = /^(.*):(\d+):in `(.*)'$/

	def colorize
		$stderr.puts self.message.colorize(:red)
		self.backtrace.each do |line|
			line = BACKTRACE_REGEXP.match line
			line = '%s:%s:in `%s\'' % [
					line[1].colorize(:yellow),
					line[2].colorize(:blue),
					line[3].colorize(:magenta)
			]
			$stderr.puts line
		end
	end
end

class Integer
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

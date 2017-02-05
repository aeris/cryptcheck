require 'ostruct'

describe CryptCheck::State do
	describe '::status' do
		it 'must handle empty list' do
			expect(CryptCheck::State.status []).to be_nil
		end

		it 'must answer correctly' do
			{
					[:critical, :critical] => :critical,
					[:critical, :error]    => :critical,
					[:critical, :warning]  => :critical,
					[:critical, nil]       => :critical,
					[:critical, :good]     => :critical,
					[:critical, :perfect]  => :critical,
					[:critical, :best]     => :critical,

					[:error, :critical]    => :critical,
					[:error, :error]       => :error,
					[:error, :warning]     => :error,
					[:error, nil]          => :error,
					[:error, :good]        => :error,
					[:error, :perfect]     => :error,
					[:error, :best]        => :error,

					[:warning, :critical]  => :critical,
					[:warning, :error]     => :error,
					[:warning, :warning]   => :warning,
					[:warning, nil]        => :warning,
					[:warning, :good]      => :warning,
					[:warning, :perfect]   => :warning,
					[:warning, :best]      => :warning,

					[:good, :critical]     => :critical,
					[:good, :error]        => :error,
					[:good, :warning]      => :warning,
					[:good, nil]           => :good,
					[:good, :good]         => :good,
					[:good, :perfect]      => :good,
					[:good, :best]         => :good,

					[:perfect, :critical]  => :critical,
					[:perfect, :error]     => :error,
					[:perfect, :warning]   => :warning,
					[:perfect, nil]        => :perfect,
					[:perfect, :good]      => :good,
					[:perfect, :perfect]   => :perfect,
					[:perfect, :best]      => :perfect,

					[:best, :critical]     => :critical,
					[:best, :error]        => :error,
					[:best, :warning]      => :warning,
					[:best, nil]           => :best,
					[:best, :good]         => :good,
					[:best, :perfect]      => :perfect,
					[:best, :best]         => :best
			}.each do |levels, result|
				got = CryptCheck::State.status levels
				expect(got).to be(result), "#{levels} : expected #{result.inspect}, got #{got.inspect}"
			end
		end

		it 'must handle object list' do
			critical = OpenStruct.new status: :critical
			warning  = OpenStruct.new status: :warning
			expect(CryptCheck::State.status [critical, warning]).to be :critical
		end
	end

	describe '::problem' do
		it 'must answer correctly' do
			{
					[:critical, :critical] => :critical,
					[:critical, :error]    => :critical,
					[:critical, :warning]  => :critical,
					[:critical, nil]       => :critical,
					[:critical, :good]     => :critical,
					[:critical, :perfect]  => :critical,
					[:critical, :best]     => :critical,

					[:error, :critical]    => :critical,
					[:error, :error]       => :error,
					[:error, :warning]     => :error,
					[:error, nil]          => :error,
					[:error, :good]        => :error,
					[:error, :perfect]     => :error,
					[:error, :best]        => :error,

					[:warning, :critical]  => :critical,
					[:warning, :error]     => :error,
					[:warning, :warning]   => :warning,
					[:warning, nil]        => :warning,
					[:warning, :good]      => :warning,
					[:warning, :perfect]   => :warning,
					[:warning, :best]      => :warning,

					[:good, :critical]     => :critical,
					[:good, :error]        => :error,
					[:good, :warning]      => :warning,
					[:good, nil]           => nil,
					[:good, :good]         => nil,
					[:good, :perfect]      => nil,
					[:good, :best]         => nil,

					[:perfect, :critical]  => :critical,
					[:perfect, :error]     => :error,
					[:perfect, :warning]   => :warning,
					[:perfect, nil]        => nil,
					[:perfect, :good]      => nil,
					[:perfect, :perfect]   => nil,
					[:perfect, :best]      => nil,

					[:best, :critical]     => :critical,
					[:best, :error]        => :error,
					[:best, :warning]      => :warning,
					[:best, nil]           => nil,
					[:best, :good]         => nil,
					[:best, :perfect]      => nil,
					[:best, :best]         => nil
			}.each do |levels, result|
				got = CryptCheck::State.problem levels
				expect(got).to be(result), "#{levels} : expected #{result.inspect}, got #{got.inspect}"
			end
		end

		it 'must handle object list' do
			critical = OpenStruct.new status: :critical
			warning  = OpenStruct.new status: :warning
			expect(CryptCheck::State.problem [critical, warning]).to be :critical
		end
	end

	describe '#states' do
		def match_states(actual, **expected)
			expected = ::CryptCheck::State.empty.merge expected
			expect(actual.states).to eq expected
		end

		let(:empty) do
			Class.new do
				include ::CryptCheck::State

				def checks
					[]
				end
			end.new
		end
		let(:childless) do
			Class.new do
				include ::CryptCheck::State

				def checks
					[
							[:foo, -> (_) { true }, :critical],
							[:bar, -> (_) { :error }],
							[:baz, -> (_) { false }]
					]
				end
			end.new
		end
		let(:parent) do
			child = Class.new do
				include ::CryptCheck::State

				def checks
					[[:bar, -> (_) { :error }]]
				end
			end.new
			Class.new do
				include ::CryptCheck::State

				def initialize(child)
					@child = child
				end

				def checks
					[[:foo, -> (_) { :critical }]]
				end

				def children
					[@child]
				end
			end.new(child)
		end
		let(:duplicated) do
			child = Class.new do
				include ::CryptCheck::State

				def checks
					[[:foo, -> (_) { :critical }]]
				end
			end.new
			Class.new do
				include ::CryptCheck::State

				def initialize(child)
					@child = child
				end

				def checks
					[[:foo, -> (_) { :critical }]]
				end

				def children
					[@child]
				end
			end.new(child)
		end

		it 'must return empty if no check nor child' do
			match_states empty
		end

		it 'must return personal status if no child' do
			match_states childless, critical: %i(foo), error: %i(bar)
		end

		it 'must return personal and children statuses' do
			match_states parent, critical: %i(foo), error: %i(bar)
		end

		it 'must return remove duplicated status' do
			match_states duplicated, critical: %i(foo)
		end
	end

	describe '#status' do
		it 'must return nil if nothing special' do
			empty = Class.new do
				include ::CryptCheck::State

				def checks
					[]
				end
			end.new
			expect(empty.status).to be_nil
		end

		it 'must return the status if only one' do
			empty = Class.new do
				include ::CryptCheck::State

				def checks
					[[:foo, -> (_) { :critical }]]
				end
			end.new
			expect(empty.status).to be :critical
		end

		it 'must return the worst status if multiple' do
			empty = Class.new do
				include ::CryptCheck::State

				def checks
					[[:foo, -> (_) { :critical }],
					 [:bar, -> (_) { :error }]]
				end
			end.new
			expect(empty.status).to be :critical
		end
	end
end

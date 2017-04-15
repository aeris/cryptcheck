require 'ostruct'

module CryptCheck
	describe State do
		describe '::status' do
			it 'must handle empty list' do
				expect(State.status []).to be_nil
			end

			it 'must answer correctly' do
				{
						[:critical, :critical] => :critical,
						[:critical, :error]    => :critical,
						[:critical, :warning]  => :critical,
						[:critical, nil]       => :critical,
						[:critical, :good]     => :critical,
						[:critical, :great]    => :critical,
						[:critical, :best]     => :critical,

						[:error, :critical]    => :critical,
						[:error, :error]       => :error,
						[:error, :warning]     => :error,
						[:error, nil]          => :error,
						[:error, :good]        => :error,
						[:error, :great]       => :error,
						[:error, :best]        => :error,

						[:warning, :critical]  => :critical,
						[:warning, :error]     => :error,
						[:warning, :warning]   => :warning,
						[:warning, nil]        => :warning,
						[:warning, :good]      => :warning,
						[:warning, :great]     => :warning,
						[:warning, :best]      => :warning,

						[:good, :critical]     => :critical,
						[:good, :error]        => :error,
						[:good, :warning]      => :warning,
						[:good, nil]           => :good,
						[:good, :good]         => :good,
						[:good, :great]        => :good,
						[:good, :best]         => :good,

						[:great, :critical]    => :critical,
						[:great, :error]       => :error,
						[:great, :warning]     => :warning,
						[:great, nil]          => :great,
						[:great, :good]        => :good,
						[:great, :great]       => :great,
						[:great, :best]        => :great,

						[:best, :critical]     => :critical,
						[:best, :error]        => :error,
						[:best, :warning]      => :warning,
						[:best, nil]           => :best,
						[:best, :good]         => :good,
						[:best, :great]        => :great,
						[:best, :best]         => :best
				}.each do |levels, result|
					got = State.status levels
					expect(got).to be(result), "#{levels} : expected #{result.inspect}, got #{got.inspect}"
				end
			end

			it 'must handle object list' do
				critical = OpenStruct.new status: :critical
				warning  = OpenStruct.new status: :warning
				expect(State.status [critical, warning]).to be :critical
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
						[:critical, :great]    => :critical,
						[:critical, :best]     => :critical,

						[:error, :critical]    => :critical,
						[:error, :error]       => :error,
						[:error, :warning]     => :error,
						[:error, nil]          => :error,
						[:error, :good]        => :error,
						[:error, :great]       => :error,
						[:error, :best]        => :error,

						[:warning, :critical]  => :critical,
						[:warning, :error]     => :error,
						[:warning, :warning]   => :warning,
						[:warning, nil]        => :warning,
						[:warning, :good]      => :warning,
						[:warning, :great]     => :warning,
						[:warning, :best]      => :warning,

						[:good, :critical]     => :critical,
						[:good, :error]        => :error,
						[:good, :warning]      => :warning,
						[:good, nil]           => nil,
						[:good, :good]         => nil,
						[:good, :great]        => nil,
						[:good, :best]         => nil,

						[:great, :critical]    => :critical,
						[:great, :error]       => :error,
						[:great, :warning]     => :warning,
						[:great, nil]          => nil,
						[:great, :good]        => nil,
						[:great, :great]       => nil,
						[:great, :best]        => nil,

						[:best, :critical]     => :critical,
						[:best, :error]        => :error,
						[:best, :warning]      => :warning,
						[:best, nil]           => nil,
						[:best, :good]         => nil,
						[:best, :great]        => nil,
						[:best, :best]         => nil
				}.each do |levels, result|
					got = State.problem levels
					expect(got).to be(result), "#{levels} : expected #{result.inspect}, got #{got.inspect}"
				end
			end

			it 'must handle object list' do
				critical = OpenStruct.new status: :critical
				warning  = OpenStruct.new status: :warning
				expect(State.problem [critical, warning]).to be :critical
			end
		end

		describe '#states' do
			def match_states(obj, **expected)
				expected = State.empty.merge expected
				expect(obj.states).to eq expected
			end


			let(:empty) do
				Class.new do
					include State

					def available_checks
						[]
					end
				end.new
			end
			let(:childless) do
				Class.new do
					include State

					def available_checks
						[
								[:foo, :critical, -> (_) { true }],
								[:bar, :error, -> (_) { true }],
								[:baz, :warning, -> (_) { false }]
						]
					end
				end.new
			end
			let(:parent) do
				child = Class.new do
					include State

					def available_checks
						[[:bar, :error, -> (_) { true }]]
					end
				end.new
				Class.new do
					include State

					def initialize(child)
						@child = child
					end

					def available_checks
						[[:foo, :critical, -> (_) { true }]]
					end

					def children
						[@child]
					end
				end.new child
			end
			let(:duplicated) do
				child = Class.new do
					include State

					def available_checks
						[[:foo, :error, -> (_) { true }]]
					end
				end.new
				Class.new do
					include State

					def initialize(child)
						@child = child
					end

					def available_checks
						[[:foo, :critical, -> (_) { true }]]
					end

					def children
						[@child]
					end
				end.new(child)
			end

			it 'must return the level if single level specified' do
				obj = Class.new do
					include State

					def available_checks
						[[:foo, :critical, -> (_) { true }]]
					end
				end.new
				match_states obj, critical: { foo: true }

				obj = Class.new do
					include State

					def available_checks
						[[:foo, :critical, -> (_) { false }]]
					end
				end.new
				match_states obj, critical: { foo: false }

				obj = Class.new do
					include State

					def available_checks
						[[:foo, :critical, -> (_) { nil }]]
					end
				end.new
				match_states obj, critical: { foo: nil }
			end

			it 'must return all levels if multiple levels specified' do
				obj = Class.new do
					include State

					def available_checks
						[[:foo, %i(critical error good great), -> (_) { :critical }]]
					end
				end.new
				match_states obj, critical: { foo: true },
							 error:         { foo: true },
							 good:          { foo: false },
							 great:         { foo: false }

				obj = Class.new do
					include State

					def available_checks
						[[:foo, %i(critical error good great), -> (_) { :error }]]
					end
				end.new
				match_states obj, critical: { foo: false },
							 error:         { foo: true },
							 good:          { foo: false },
							 great:         { foo: false }


				obj = Class.new do
					include State

					def available_checks
						[[:foo, %i(critical error good great), -> (_) { :great }]]
					end
				end.new
				match_states obj, critical: { foo: false },
							 error:         { foo: false },
							 good:          { foo: true },
							 great:         { foo: true }


				obj = Class.new do
					include State

					def available_checks
						[[:foo, %i(critical error good great), -> (_) { :good }]]
					end
				end.new
				match_states obj, critical: { foo: false },
							 error:         { foo: false },
							 good:          { foo: true },
							 great:         { foo: false }

				obj = Class.new do
					include State

					def available_checks
						[[:foo, %i(critical error good great), -> (_) { nil }]]
					end
				end.new
				match_states obj, critical: { foo: nil },
							 error:         { foo: nil },
							 good:          { foo: nil },
							 great:         { foo: nil }
			end

			it 'must return empty if no check nor child' do
				match_states empty
			end

			it 'must return personal status if no child' do
				match_states childless, critical: { foo: true }, error: { bar: true }, warning: { baz: false }
			end

			it 'must return personal and children statuses' do
				match_states parent, critical: { foo: true }, error: { bar: true }
			end

			it 'must return remove duplicated status' do
				match_states duplicated, critical: { foo: true }, error: { foo: true }
			end
		end

		describe '#status' do
			it 'must return nil if nothing special' do
				empty = Class.new do
					include State

					def available_checks
						[]
					end
				end.new
				expect(empty.status).to be_nil
			end

			it 'must return the status if only one' do
				empty = Class.new do
					include State

					def available_checks
						[[:foo, :critical, -> (_) { true }]]
					end
				end.new
				expect(empty.status).to be :critical
			end

			it 'must return the worst status if multiple' do
				empty = Class.new do
					include State

					def available_checks
						[[:foo, :critical, -> (_) { true }],
						 [:bar, :error, -> (_) { true }]]
					end
				end.new
				expect(empty.status).to be :critical
			end
		end

		describe '::state' do
			it 'must return false on bad case with nothing' do
				states = { critical: {} }
				expect(State.state states, :critical).to be_falsey
			end

			it 'must return false on bad case with only nil' do
				states = { critical: { foo: nil } }
				expect(State.state states, :critical).to be_falsey
			end

			it 'must return false on bad case with all false or nil' do
				states = { critical: { foo: false, bar: nil } }
				expect(State.state states, :critical).to be_falsey
			end

			it 'must return true on bad case with a single true' do
				states = { critical: { foo: false, bar: nil, baz: true } }
				expect(State.state states, :critical).to be_truthy
			end

			it 'must return :all on good case with nothing' do
				states = { best: {} }
				expect(State.state states, :best).to eq :all
			end

			it 'must return :all on good case with only nil' do
				states = { best: { foo: nil } }
				expect(State.state states, :best).to eq :all
			end

			it 'must return false on good case with only false' do
				states = { best: { foo: false } }
				expect(State.state states, :best).to be_falsey
			end

			it 'must return false on good case with only false or nil' do
				states = { best: { foo: false, bar: nil } }
				expect(State.state states, :best).to be_falsey
			end

			it 'must return :some on good case with a single true' do
				states = { best: { foo: false, bar: nil, baz: true } }
				expect(State.state states, :best).to eq :some
			end

			it 'must return :all on good case with only true' do
				states = { best: { bar: true } }
				expect(State.state states, :best).to eq :all
			end

			it 'must return :all on good case with only true or nil' do
				states = { best: { foo: nil, bar: true } }
				expect(State.state states, :best).to eq :all
			end
		end
	end
end

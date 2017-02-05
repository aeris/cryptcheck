describe CryptCheck::Statused do
	def match_status(actual, **expected)
		expected = ::CryptCheck::Status.empty.merge expected
		expect(actual.status).to eq expected
	end

	describe '::status' do
		it 'must return empty if no check nor child' do
			statused = Class.new do
				include ::CryptCheck::Statused
			end.new
			match_status statused
		end

		it 'must return personal status if no child' do
			statused = Class.new do
				include ::CryptCheck::Statused

				def checks
					[
							[:foo, -> (_) { true }, :critical],
							[:bar, -> (_) { :error }],
							[:baz, -> (_) { false }]
					]
				end
			end.new
			match_status statused, critical: %i(foo), error: %i(bar)
		end

		it 'must return personal and children statuses' do
			child  = Class.new do
				include ::CryptCheck::Statused

				def checks
					[[:bar, -> (_) { :error }]]
				end
			end.new
			parent = Class.new do
				include ::CryptCheck::Statused

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
			match_status parent, critical: %i(foo), error: %i(bar)
		end

		it 'must return remove duplicated status' do
			child  = Class.new do
				include ::CryptCheck::Statused

				def checks
					[[:foo, -> (_) { :critical }]]
				end
			end.new
			parent = Class.new do
				include ::CryptCheck::Statused

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
			match_status parent, critical: %i(foo)
		end
	end
end

require 'ostruct'

describe CryptCheck::Status do
	describe '::status' do
		it 'must handle empty list' do
			expect(CryptCheck::Status.status []).to be_nil
		end

		it 'must answer correctly' do
			{
					[:critical, :critical] => :critical,
					[:critical, :error]    => :critical,
					[:critical, :warning]  => :critical,
					[:critical, :good]     => :critical,
					[:critical, :perfect]  => :critical,
					[:critical, :best]     => :critical,

					[:error, :critical]    => :critical,
					[:error, :error]       => :error,
					[:error, :warning]     => :error,
					[:error, :good]        => :error,
					[:error, :perfect]     => :error,
					[:error, :best]        => :error,

					[:warning, :critical]  => :critical,
					[:warning, :error]     => :error,
					[:warning, :warning]   => :warning,
					[:warning, :good]      => :warning,
					[:warning, :perfect]   => :warning,
					[:warning, :best]      => :warning,

					[:good, :critical]     => :critical,
					[:good, :error]        => :error,
					[:good, :warning]      => :warning,
					[:good, :good]         => :good,
					[:good, :perfect]      => :good,
					[:good, :best]         => :good,

					[:perfect, :critical]  => :critical,
					[:perfect, :error]     => :error,
					[:perfect, :warning]   => :warning,
					[:perfect, :good]      => :good,
					[:perfect, :perfect]   => :perfect,
					[:perfect, :best]      => :perfect,

					[:best, :critical]     => :critical,
					[:best, :error]        => :error,
					[:best, :warning]      => :warning,
					[:best, :good]         => :good,
					[:best, :perfect]      => :perfect,
					[:best, :best]         => :best
			}.each do |levels, result|
				got = CryptCheck::Status.status levels
				expect(got).to be(result), "#{levels} : expected #{result.inspect}, got #{got.inspect}"
			end
		end

		it 'must handle object list' do
			critical = OpenStruct.new status: :critical
			warning  = OpenStruct.new status: :warning
			expect(CryptCheck::Status.status [critical, warning]).to be :critical
		end
	end

	describe '::problem' do
		it 'must answer correctly' do
			{
					[:critical, :critical] => :critical,
					[:critical, :error]    => :critical,
					[:critical, :warning]  => :critical,
					[:critical, :good]     => :critical,
					[:critical, :perfect]  => :critical,
					[:critical, :best]     => :critical,

					[:error, :critical]    => :critical,
					[:error, :error]       => :error,
					[:error, :warning]     => :error,
					[:error, :good]        => :error,
					[:error, :perfect]     => :error,
					[:error, :best]        => :error,

					[:warning, :critical]  => :critical,
					[:warning, :error]     => :error,
					[:warning, :warning]   => :warning,
					[:warning, :good]      => :warning,
					[:warning, :perfect]   => :warning,
					[:warning, :best]      => :warning,

					[:good, :critical]     => :critical,
					[:good, :error]        => :error,
					[:good, :warning]      => :warning,
					[:good, :good]         => nil,
					[:good, :perfect]      => nil,
					[:good, :best]         => nil,

					[:perfect, :critical]  => :critical,
					[:perfect, :error]     => :error,
					[:perfect, :warning]   => :warning,
					[:perfect, :good]      => nil,
					[:perfect, :perfect]   => nil,
					[:perfect, :best]      => nil,

					[:best, :critical]     => :critical,
					[:best, :error]        => :error,
					[:best, :warning]      => :warning,
					[:best, :good]         => nil,
					[:best, :perfect]      => nil,
					[:best, :best]         => nil
			}.each do |levels, result|
				got = CryptCheck::Status.problem levels
				expect(got).to be(result), "#{levels} : expected #{result.inspect}, got #{got.inspect}"
			end
		end

		it 'must handle object list' do
			critical = OpenStruct.new status: :critical
			warning  = OpenStruct.new status: :warning
			expect(CryptCheck::Status.problem [critical, warning]).to be :critical
		end
	end
end

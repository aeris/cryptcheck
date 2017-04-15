module CryptCheck::Tls
	describe Method do
		describe '#==' do
			it 'must be equals to corresponding symbol' do
				method = Method[:TLSv1_2]
				expect(method == :SSLv2).to be false
				expect(method == :SSLv3).to be false
				expect(method == :TLSv1).to be false
				expect(method == :TLSv1_1).to be false
				expect(method == :TLSv1_2).to be true
			end

			it 'must be equals to corresponding method' do
				method = Method[:TLSv1_2]
				expect(method == Method[:SSLv2]).to be false
				expect(method == Method[:SSLv3]).to be false
				expect(method == Method[:TLSv1]).to be false
				expect(method == Method[:TLSv1_1]).to be false
				expect(method == Method[:TLSv1_2]).to be true
			end
		end

		# describe '#eql?' do
		# 	it 'must be equals to corresponding symbol' do
		# 		method = Method[:TLSv1_2]
		# 		expect(method.eql? :SSLv2).to be false
		# 		expect(method.eql? :SSLv3).to be false
		# 		expect(method.eql? :TLSv1).to be false
		# 		expect(method.eql? :TLSv1_1).to be false
		# 		expect(method.eql? :TLSv1_2).to be true
		# 	end
		#
		# 	it 'must be equals to corresponding method' do
		# 		method = Method[:TLSv1_2]
		# 		expect(method.eql? Method[:SSLv2]).to be false
		# 		expect(method.eql? Method[:SSLv3]).to be false
		# 		expect(method.eql? Method[:TLSv1]).to be false
		# 		expect(method.eql? Method[:TLSv1_1]).to be false
		# 		expect(method.eql? Method[:TLSv1_2]).to be true
		# 	end
		# end
		#
		# describe '#equal?' do
		# 	it 'must be equals to corresponding symbol' do
		# 		method = Method[:TLSv1_2]
		# 		expect(method.equal? :SSLv2).to be false
		# 		expect(method.equal? :SSLv3).to be false
		# 		expect(method.equal? :TLSv1).to be false
		# 		expect(method.equal? :TLSv1_1).to be false
		# 		expect(method.equal? :TLSv1_2).to be true
		# 	end
		#
		# 	it 'must be equals to corresponding method' do
		# 		method = Method[:TLSv1_2]
		# 		expect(method.equal? Method[:SSLv2]).to be false
		# 		expect(method.equal? Method[:SSLv3]).to be false
		# 		expect(method.equal? Method[:TLSv1]).to be false
		# 		expect(method.equal? Method[:TLSv1_1]).to be false
		# 		expect(method.equal? Method[:TLSv1_2]).to be true
		# 	end
		# end
	end
end

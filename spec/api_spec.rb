require 'sslcheck'

module SSLCheck::SSLLabs
	describe API do
		URL = 'https://www.ssllabs.com/ssltest/analyze.html'

		it 'error' do
			stub_request(:get, URL).with(query: { d: 'imirhil.fr'})
				.to_return(status: 500)
			expect { API.new 'imirhil.fr' } .to  raise_error ServerError, '500'
		end

		it 'waiting' do
			stub_request(:get, URL).with(query: { d: 'imirhil.fr'})
				.to_return(status: 200, body: File.read('spec/html/waiting.html'))
			expect { API.new 'imirhil.fr' } .to raise_error WaitingError
		end

		it 'single' do
			stub_request(:get, URL).with(query: { d: 'imirhil.fr'})
			.to_return(status: 200, body: File.read('spec/html/perfect.html'))
			results = API.new 'imirhil.fr'
			expect(results.hostname).to eq 'imirhil.fr'
			expect(results.ip).to eq '5.135.187.37'
			expect(results.rank).to eq 'A+'
			expect(results.ssl).to be false
			expect(results.tls).to be true
			expect(results.rc4).to be false
			expect(results.pfs).to be true
			expect(results.hsts).to be true
			expect(results.bits).to be 128
		end

		it 'multiple' do
			stub_request(:get, URL).with(query: { d: 'fortuneo.fr'})
				.to_return(status: 200, body: File.read('spec/html/multiple.html'))
			stub_request(:get, URL).with(query: { d: 'fortuneo.fr', s: '93.20.46.72'})
				.to_return(status: 200, body: File.read('spec/html/results.html'))
			results = API.new 'fortuneo.fr'
			expect(results.hostname).to eq 'fortuneo.fr'
			expect(results.ip).to eq '194.51.217.72'
			expect(results.rank).to eq 'B'
			expect(results.ssl).to be true
			expect(results.tls).to be false
			expect(results.rc4).to be true
			expect(results.pfs).to be false
			expect(results.hsts).to be false
			expect(results.bits).to be 128
		end
	end
end

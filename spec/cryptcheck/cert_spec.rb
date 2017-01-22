describe CryptCheck::Tls::Cert do
	def load_chain(chain)
		chain.collect { |f| ::OpenSSL::X509::Certificate.new File.read File.join 'spec/resources', "#{f}.crt" }
	end

	describe '::trusted?' do
		it 'must accept valid certificat' do
			cert, *chain, ca = load_chain %w(custom intermediate ca)
			trust                  = ::CryptCheck::Tls::Cert.trusted? cert, chain, roots: ca
			expect(trust).to eq :trusted
		end

		it 'must reject self signed certificate' do
			cert, ca = load_chain %w(self-signed ca)
			trust                  = ::CryptCheck::Tls::Cert.trusted? cert, [], roots: ca
			expect(trust).to eq 'self signed certificate'
		end

		it 'must reject unknown CA' do
			cert, *chain = load_chain %w(custom intermediate ca)
			trust        = ::CryptCheck::Tls::Cert.trusted? cert, chain, roots: []
			expect(trust).to eq 'unable to get issuer certificate'
		end

		it 'must reject missing intermediate chain' do
			cert, ca = load_chain %w(custom ca)
			chain   = []
			trust   = ::CryptCheck::Tls::Cert.trusted? cert, chain, roots: ca
			expect(trust).to eq 'unable to get local issuer certificate'
		end
	end
end

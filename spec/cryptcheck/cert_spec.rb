require 'faketime'

describe CryptCheck::Tls::Cert do
	def load_chain(chain)
		chain.collect { |f| ::OpenSSL::X509::Certificate.new File.read "spec/resources/#{f}.crt" }
	end

	describe '::trusted?' do
		it 'must accept valid certificate' do
			FakeTime.freeze_during Time.utc(2000, 1, 1) do
				cert, *chain, ca = load_chain %w(ecdsa-prime256v1 intermediate ca)
				trust            = ::CryptCheck::Tls::Cert.trusted? cert, chain, roots: ca
				expect(trust).to eq :trusted
			end
		end

		it 'must reject self signed certificate' do
			cert, ca = load_chain %w(self-signed ca)
			trust    = ::CryptCheck::Tls::Cert.trusted? cert, [], roots: ca
			expect(trust).to eq 'self signed certificate'
		end

		it 'must reject unknown CA' do
			cert, *chain = load_chain %w(ecdsa-prime256v1 intermediate ca)
			trust        = ::CryptCheck::Tls::Cert.trusted? cert, chain, roots: []
			expect(trust).to eq 'unable to get issuer certificate'
		end

		it 'must reject missing intermediate chain' do
			cert, ca = load_chain %w(ecdsa-prime256v1 ca)
			chain    = []
			trust    = ::CryptCheck::Tls::Cert.trusted? cert, chain, roots: ca
			expect(trust).to eq 'unable to get local issuer certificate'
		end

		it 'must reject expired certificate' do
			FakeTime.freeze_during Time.utc(2002, 1, 1) do
				cert, *chain, ca = load_chain %w(ecdsa-prime256v1 intermediate ca)
				trust            = ::CryptCheck::Tls::Cert.trusted? cert, chain, roots: ca
				expect(trust).to eq 'certificate has expired'
			end
		end

		it 'must reject not yet valid certificate' do
			FakeTime.freeze_during Time.utc(1999, 1, 1) do
				cert, *chain, ca = load_chain %w(ecdsa-prime256v1 intermediate ca)
				trust            = ::CryptCheck::Tls::Cert.trusted? cert, chain, roots: ca
				expect(trust).to eq 'certificate is not yet valid'
			end
		end
	end
end

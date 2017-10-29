module CryptCheck::Tls
	describe Cert do
		around :each do |example|
			FakeTime.freeze(Time.utc 2000, 6, 1) { example.run }
		end

		describe '::trusted?' do
			it 'must accept valid certificate' do
				cert, *chain, ca = chain(%w(ecdsa-prime256v1 intermediate ca))
				trust            = Cert.trusted? cert, chain, roots: ca
				expect(trust).to eq :trusted
			end

			it 'must reject self signed certificate' do
				cert, ca = chain(%w(self-signed ca))
				trust    = Cert.trusted? cert, [], roots: ca
				expect(trust).to eq 'self signed certificate'

				# Case for SSLv2
				cert, ca = chain(%w(self-signed ca))
				trust    = Cert.trusted? cert, nil, roots: ca
				expect(trust).to eq 'self signed certificate'
			end

			it 'must reject unknown CA' do
				cert, *chain = chain(%w(ecdsa-prime256v1 intermediate ca))
				trust        = Cert.trusted? cert, chain, roots: []
				expect(trust).to eq 'unable to get issuer certificate'
			end

			it 'must reject missing intermediate chain' do
				cert, ca = chain(%w(ecdsa-prime256v1 ca))
				chain    = []
				trust    = Cert.trusted? cert, chain, roots: ca
				expect(trust).to eq 'unable to get local issuer certificate'
			end

			it 'must reject expired certificate' do
				FakeTime.freeze Time.utc(2002, 1, 1) do
					cert, *chain, ca = chain(%w(ecdsa-prime256v1 intermediate ca))
					trust            = Cert.trusted? cert, chain, roots: ca
					expect(trust).to eq 'certificate has expired'
				end
			end

			it 'must reject not yet valid certificate' do
				FakeTime.freeze Time.utc(1999, 1, 1) do
					cert, *chain, ca = chain(%w(ecdsa-prime256v1 intermediate ca))
					trust            = Cert.trusted? cert, chain, roots: ca
					expect(trust).to eq 'certificate is not yet valid'
				end
			end
		end

		describe '#md5?' do
			it 'must detect md5 certificate' do
				cert = Cert.new cert(:md5)
				expect(cert.md5?).to be true

				cert = Cert.new cert(:sha1)
				expect(cert.md5?).to be false

				cert = Cert.new cert(:ecdsa, :prime256v1)
				expect(cert.md5?).to be false
			end
		end

		describe '#sha1?' do
			it 'must detect sha1 certificate' do
				cert = Cert.new cert(:md5)
				expect(cert.sha1?).to be false

				cert = Cert.new cert(:sha1)
				expect(cert.sha1?).to be true

				cert = Cert.new cert(:ecdsa, :prime256v1)
				expect(cert.sha1?).to be false
			end
		end

		describe '#sha2?' do
			it 'must detect sha2 certificate' do
				cert = Cert.new cert(:md5)
				expect(cert.sha2?).to be false

				cert = Cert.new cert(:sha1)
				expect(cert.sha2?).to be false

				cert = Cert.new cert(:ecdsa, :prime256v1)
				expect(cert.sha2?).to be true
			end
		end
	end
end

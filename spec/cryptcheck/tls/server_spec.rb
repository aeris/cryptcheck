describe CryptCheck::Tls::Server do
	before :all do
		FakeTime.freeze Time.utc(2000, 1, 1)
	end

	after :all do
		FakeTime.unfreeze
	end

	default_parameters       = {
			methods:           %i(TLSv1_2),
			chain:             %w(intermediate ca),
			curves:            %i(prime256v1),
			server_preference: true
	}.freeze
	default_ecdsa_parameters = default_parameters.merge({
																material: [[:ecdsa, :prime256v1]],
																ciphers:  %i(ECDHE-ECDSA-AES128-SHA),
																curves:   %i(prime256v1)
														}).freeze
	default_rsa_parameters   = default_parameters.merge({
																material: [[:rsa, 1024]],
																ciphers:  %i(ECDHE-RSA-AES128-SHA),
																curves:   %i(prime256v1),
																dh:       1024
														}).freeze
	default_mixed_parameters = default_parameters.merge({
																material: [[:ecdsa, :prime256v1], [:rsa, 1024]],
																ciphers:  %i(ECDHE-ECDSA-AES128-SHA ECDHE-RSA-AES128-SHA),
																curves:   %i(prime256v1),
																dh:       1024
														}).freeze
	default_sslv2_parameters = default_parameters.merge({
																methods:  :SSLv2,
																material: [[:rsa, 1024]],
																ciphers:  %i(RC4-MD5),
																chain:    []
														}).freeze
	DEFAULT_PARAMETERS       = { ecdsa: default_ecdsa_parameters.freeze,
								 rsa:   default_rsa_parameters.freeze,
								 mixed: default_mixed_parameters.freeze,
								 sslv2: default_sslv2_parameters.freeze }.freeze

	def server(type=:ecdsa, **kargs)
		params = DEFAULT_PARAMETERS[type].dup
		params.merge!(kargs) if kargs
		host, port = '127.0.0.1', 15000
		params.merge!({ host: host, port: port })
		tls_serv **params do
			CryptCheck::Tls::TcpServer.new 'localhost', ::Socket::PF_INET, host, port
		end
	end

	describe '#certs' do
		it 'must detect RSA certificate' do
			certs = server(:rsa).certs.collect &:fingerprint
			expect(certs).to match_array %w(a11802a4407aaeb93ccd0bd8c8a61be17eaba6b378433af5ad45ecbb1d633f71)
		end

		it 'must detect ECDSA certificate' do
			certs = server.certs.collect &:fingerprint
			expect(certs).to match_array %w(531ab9545f052818ff0559f648a147b104223834cc8f780516b3aacf1fdc8c06)
		end

		it 'must detect RSA and ECDSA certificates' do
			certs = server(:mixed).certs.collect &:fingerprint
			expect(certs).to match_array %w(531ab9545f052818ff0559f648a147b104223834cc8f780516b3aacf1fdc8c06
												a11802a4407aaeb93ccd0bd8c8a61be17eaba6b378433af5ad45ecbb1d633f71)
		end
	end

	describe '#supported_methods' do
		it 'must detect SSLv2' do
			s       = server :sslv2
			methods = s.supported_methods.collect &:to_sym
			expect(methods).to match_array %i(SSLv2)
		end

		it 'must detect SSLv3' do
			server  = server methods: %i(SSLv3)
			methods = server.supported_methods.collect &:to_sym
			expect(methods).to match_array %i(SSLv3)
		end

		it 'must detect TLSv1.0' do
			server  = server methods: %i(TLSv1)
			methods = server.supported_methods.collect &:to_sym
			expect(methods).to match_array %i(TLSv1)
		end

		it 'must detect TLSv1.1' do
			server  = server methods: %i(TLSv1_1)
			methods = server.supported_methods.collect &:to_sym
			expect(methods).to match_array %i(TLSv1_1)
		end

		it 'must detect TLSv1.2' do
			server  = server methods: %i(TLSv1_2)
			methods = server.supported_methods.collect &:to_sym
			expect(methods).to match_array %i(TLSv1_2)
		end

		it 'must detect mixed methods' do
			server  = server methods: %i(SSLv3 TLSv1 TLSv1_1 TLSv1_2)
			methods = server.supported_methods.collect &:to_sym
			expect(methods).to match_array %i(SSLv3 TLSv1 TLSv1_1 TLSv1_2)
		end
	end

	describe '#supported_ciphers' do
		it 'must detect supported cipher' do
			ciphers = server.supported_ciphers
							  .map { |k, v| [k.to_sym, v.keys.collect(&:name)] }
							  .to_h[:TLSv1_2]
			expect(ciphers).to match_array %w(ECDHE-ECDSA-AES128-SHA)
		end
	end

	describe '#supported_curves' do
		it 'must detect no supported curves' do
			s      = server :rsa, ciphers: %w(AES128-SHA)
			curves = s.supported_curves.collect &:name
			expect(curves).to be_empty
		end

		it 'must detect supported curves for RSA' do
			s      = server :rsa, curves: %i(prime256v1 sect571r1)
			curves = s.supported_curves.collect &:name
			expect(curves).to contain_exactly :prime256v1, :sect571r1
		end

		it 'must detect supported curves from ECDSA' do
			server = server server_preference: false
			curves = server.supported_curves.collect &:name
			expect(curves).to contain_exactly :prime256v1
		end

		it 'must detect supported curves from ECDSA and ECDHE' do
			server = server curves: %i(prime256v1 sect571r1), server_preference: false
			curves = server.supported_curves.collect &:name
			expect(curves).to contain_exactly :prime256v1, :sect571r1
		end

		# No luck here :'(
		it 'can\'t detect supported curves from ECDHE if server preference enforced' do
			server = server curves: %i(prime256v1 sect571r1)
			curves = server.supported_curves.collect &:name
			expect(curves).to contain_exactly :prime256v1

			server = server curves: %i(sect571r1 prime256v1)
			curves = server.supported_curves.collect &:name
			expect(curves).to contain_exactly :prime256v1, :sect571r1
		end
	end

	describe '#curves_preference' do
		it 'must report N/A if no curve on RSA' do
			s      = server :rsa, ciphers: %w(AES128-GCM-SHA256)
			curves = s.curves_preference
			expect(curves).to be_nil

			s      = server :rsa, ciphers: %w(AES128-GCM-SHA256), server_preference: false
			curves = s.curves_preference
			expect(curves).to be_nil
		end

		it 'must report N/A if a single curve on RSA' do
			curves = server(:rsa).curves_preference
			expect(curves).to be_nil

			curves = server(:rsa, server_preference: false).curves_preference
			expect(curves).to be_nil
		end

		it 'must report server preference if server preference enforced on RSA' do
			s      = server :rsa, curves: %i(prime256v1 sect571r1)
			curves = s.curves_preference.collect &:name
			expect(curves).to eq %i(prime256v1 sect571r1)

			s      = server :rsa, curves: %i(sect571r1 prime256v1)
			curves = s.curves_preference.collect &:name
			expect(curves).to eq %i(sect571r1 prime256v1)
		end

		it 'must report client preference if server preference not enforced on RSA' do
			s      = server :rsa, curves: %i(prime256v1 sect571r1), server_preference: false
			curves = s.curves_preference
			expect(curves).to be :client

			s      = server :rsa, curves: %i(sect571r1 prime256v1), server_preference: false
			curves = s.curves_preference
			expect(curves).to be :client
		end

		it 'must report N/A if a single curve on ECDSA' do
			curves = server.curves_preference
			expect(curves).to be_nil

			curves = server(server_preference: false).curves_preference
			expect(curves).to be_nil
		end

		# No luck here :'(
		it 'can\'t detect server preference if server preference enforced on ECDSA with preference on ECDSA curve' do
			curves = server(curves: %i(prime256v1 sect571r1)).curves_preference
			expect(curves).to be_nil
		end

		it 'must report server preference if server preference enforced on ECDSA with preference not on ECDSA curve' do
			s      = server curves: %i(sect571r1 prime256v1)
			curves = s.curves_preference.collect &:name
			expect(curves).to eq %i(sect571r1 prime256v1)
		end

		it 'must report client preference if server preference not enforced on ECDSA' do
			s      = server curves: %i(prime256v1 sect571r1), server_preference: false
			curves = s.curves_preference
			expect(curves).to be :client

			s      = server curves: %i(sect571r1 prime256v1), server_preference: false
			curves = s.curves_preference
			expect(curves).to be :client
		end
	end
end

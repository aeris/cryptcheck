describe CryptCheck::Tls do
	def server(*args, &block)
		tls_serv *args, &block
	end

	def plain_server(*args, &block)
		plain_serv *args, &block
	end

	def analyze(*args)
		CryptCheck::Tls.analyze *args
	end

	include_examples :analysis
end

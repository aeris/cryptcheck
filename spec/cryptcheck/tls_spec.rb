describe CryptCheck::Tls do
	def process
	end

	def analyze(*args)
		CryptCheck::Tls.analyze *args
	end

	include_examples :analysis
end

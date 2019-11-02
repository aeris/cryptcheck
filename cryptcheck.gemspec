# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

Gem::Specification.new do |spec|
	spec.name    = 'cryptcheck'
	spec.version = '2.0.0'
	spec.authors = ['Aeris']
	spec.email   = ['aeris+tls@imirhil.fr']

	spec.summary     = %q{Check best practices on crypto-stack implementation}
	spec.description = %q{Verify if best practices are well implemented on current crypto-stack (TLS & SSH) protocol (HTTPS, SMTP, XMPP, SSH & VPN)}
	spec.homepage    = 'https://tls.imirhil.fr'
	spec.license     = 'AGPL-3.0+'

	if spec.respond_to?(:metadata)
		spec.metadata['allowed_push_host'] = 'TODO: Set to "http://mygemserver.com"'
	else
		raise 'RubyGems 2.0 or newer is required to protect against public gem pushes.'
	end

	spec.files         = { '*.rb' => %w(lib) }
								 .collect_concat { |e, ds| ds.collect_concat { |d| Dir[File.join d, '**', e] } }
#	spec.bindir        = 'bin'
#	spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
#	spec.test_files    = spec.files.grep(%r{^spec/})
	spec.require_paths = %w(lib)

	spec.add_development_dependency 'bundler'
	spec.add_development_dependency 'rake'
	spec.add_development_dependency 'rspec'
	spec.add_development_dependency 'ffi'
	spec.add_development_dependency 'pry-byebug'
	spec.add_development_dependency 'pry-rescue'
	spec.add_development_dependency 'pry-stack_explorer'

	spec.add_dependency 'httparty'
	spec.add_dependency 'nokogiri'
	spec.add_dependency 'parallel'
	spec.add_dependency 'ruby-progressbar'
	spec.add_dependency 'colorize'
	spec.add_dependency 'awesome_print'
	spec.add_dependency 'thor'
end

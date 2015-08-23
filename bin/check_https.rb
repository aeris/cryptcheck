#!/usr/bin/env ruby
<<<<<<< HEAD
$:.unshift 'lib'
require 'logging'
=======
$:.unshift File.expand_path File.join File.dirname(__FILE__), '../lib'
require 'rubygems'
require 'bundler/setup'
>>>>>>> 92424828e14b13f2b465b7c7426cffefe882bbbd
require 'cryptcheck'

name = ARGV[0] || 'index'
file = ::File.join 'output', "#{name}.yml"

if ::File.exist? file
<<<<<<< HEAD
	::CryptCheck::Tls::Https.analyze_from_file "output/#{name}.yml", "output/#{name}.html"
else
	::Logging.logger.root.appenders = ::Logging.appenders.stdout
	::Logging.logger.root.level = :warn

	server = ::CryptCheck::Tls::Https::Server.new(ARGV[0], ARGV[1] || 443)
	p grade = ::CryptCheck::Tls::Https::Grade.new(server)
end
=======
	::CryptCheck::Logger.level = :none
	::CryptCheck::Tls::Https.analyze_from_file "output/#{name}.yml", "output/#{name}.html"
else
	::CryptCheck::Logger.level = (ARGV[1] || :info).to_sym
	server = ::CryptCheck::Tls::Https::Server.new ARGV[0]
	grade = ::CryptCheck::Tls::Https::Grade.new server
	::CryptCheck::Logger.info { '' }
	grade.display
end
>>>>>>> 92424828e14b13f2b465b7c7426cffefe882bbbd

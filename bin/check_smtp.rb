#!/usr/bin/env ruby
$:.unshift File.expand_path File.join File.dirname(__FILE__), '../lib'
require 'rubygems'
require 'bundler/setup'
require 'logging'
require 'cryptcheck'

name = ARGV[0]
unless name
	::CryptCheck::Tls::Smtp.analyze_from_file 'output/smtp.yml', 'output/smtp.html'
else
	::Logging.logger.root.appenders = ::Logging.appenders.stdout
	::Logging.logger.root.level = :warn

	server = ::CryptCheck::Tls::Smtp::Server.new(ARGV[0], ARGV[1] || 25)
	p grade = ::CryptCheck::Tls::Smtp::Grade.new(server)
end



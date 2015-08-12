#!/usr/bin/env ruby
$:.unshift File.expand_path File.join File.dirname(__FILE__), '../lib'
require 'rubygems'
require 'bundler/setup'
require 'logging'
require 'cryptcheck'

name = ARGV[0] || 'index'
file = ::File.join 'output', "#{name}.yml"

if ::File.exist? file
	::CryptCheck::Tls::Https.analyze_from_file "output/#{name}.yml", "output/#{name}.html"
else
	::Logging.logger.root.appenders = ::Logging.appenders.stdout
	::Logging.logger.root.level = :warn

	server = ::CryptCheck::Tls::Https::Server.new(ARGV[0], ARGV[1] || 443)
	p grade = ::CryptCheck::Tls::Https::Grade.new(server)
end

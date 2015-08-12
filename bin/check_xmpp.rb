#!/usr/bin/env ruby
$:.unshift File.expand_path File.join File.dirname(__FILE__), '../lib'
require 'rubygems'
require 'bundler/setup'
require 'logging'
require 'cryptcheck'

name = ARGV[0]
if name
	::Logging.logger.root.appenders = ::Logging.appenders.stdout
	::Logging.logger.root.level = :warn

	server = ::CryptCheck::Tls::Xmpp::Server.new(name, ARGV[1] || :s2s)
	p grade = ::CryptCheck::Tls::Xmpp::Grade.new(server)
else
	::CryptCheck::Tls::Xmpp.analyze_from_file 'output/xmpp.yml', 'output/xmpp.html'
end


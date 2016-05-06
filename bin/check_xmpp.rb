#!/usr/bin/env ruby
$:.unshift File.expand_path File.join File.dirname(__FILE__), '../lib'
require 'rubygems'
require 'bundler/setup'
require 'cryptcheck'

name = ARGV[0] || 'xmpp'
file = ::File.join 'output', "#{name}.yml"
if ::File.exist? file
	::CryptCheck::Logger.level = ENV['LOG'] || :none
	::CryptCheck::Tls::Xmpp.analyze_file file, "output/#{name}.html"
else
	::CryptCheck::Logger.level = ENV['LOG'] || :info
	::CryptCheck::Tls::Xmpp.analyze_domain ARGV[0], type: (ARGV[1] || :s2s).to_sym
end

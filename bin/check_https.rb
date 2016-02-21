#!/usr/bin/env ruby
$:.unshift File.expand_path File.join File.dirname(__FILE__), '../lib'
require 'rubygems'
require 'bundler/setup'
require 'cryptcheck'

name = ARGV[0] || 'index'
file = ::File.join 'output', "#{name}.yml"
if ::File.exist? file
	::CryptCheck::Logger.level = ENV['LOG'] || :none
	::CryptCheck::Tls::Https.analyze_file file, "output/#{name}.html"
else
	::CryptCheck::Logger.level = ENV['LOG'] || :info
	::CryptCheck::Tls::Https.analyze ARGV[0], (ARGV[1] || 443)
end

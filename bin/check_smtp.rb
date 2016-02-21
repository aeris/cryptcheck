#!/usr/bin/env ruby
$:.unshift File.expand_path File.join File.dirname(__FILE__), '../lib'
require 'rubygems'
require 'bundler/setup'
require 'cryptcheck'

name = ARGV[0] || 'smtp'
file = ::File.join 'output', "#{name}.yml"
if ::File.exist? file
	::CryptCheck::Logger.level = ENV['LOG'] || :none
	::CryptCheck::Tls::Smtp.analyze_file file, "output/#{name}.html"
else
	::CryptCheck::Logger.level = ENV['LOG'] || :info
	::CryptCheck::Tls::Smtp.analyze ARGV[0]
end



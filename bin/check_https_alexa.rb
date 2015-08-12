#!/usr/bin/env ruby
$:.unshift File.expand_path File.join File.dirname(__FILE__), '../lib'
require 'rubygems'
require 'bundler/setup'
require 'logging'
require 'cryptcheck'

GROUP_NAME = 'Top 100 Alexa'

::CryptCheck::Logger.level = :none

hosts = []
::File.open('top-1m.csv', 'r') do |file|
	i = 0
	while line = file.gets
		hosts << [GROUP_NAME, line.strip.split(',')[1]]
		i += 1
		break if i == 100
	end
end

::CryptCheck::Tls::Https.analyze hosts, 'output/alexa.html'

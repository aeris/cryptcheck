#!/usr/bin/env ruby
$:.unshift File.expand_path File.join File.dirname(__FILE__), '../lib'
require 'rubygems'
require 'bundler/setup'
require 'cryptcheck'

args, port = ARGV
args = [args, port] if port
hosts = ::CryptCheck::Tls::Smtp.analyze *args
ap hosts

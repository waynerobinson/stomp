# -*- encoding: utf-8 -*-

#
# Reference: https://github.com/stompgem/stomp/wiki/extended-ssl-overview
#
require "rubygems"
require "stomp"
#
# If you use SSLParams, and need the _default_ Ruby ciphers, this is how.
#
# NOTE: JRuby users may find that this is a *required* action. YMMV.
#
ssl_opts = Stomp::SSLParams.new(:use_ruby_ciphers => true) # Plus other parameters as needed
#
# SSL Use Case: Using default Stomp ciphers
#
hash = { :hosts => [ 
      {:login => 'guest', :passcode => 'guest', :host => 'localhost', 
        :port => 61612, :ssl => ssl_opts},
      ]
    }
#
puts "Connect starts, SSL , Use Default Ruby Ciphers"
c = Stomp::Connection.new(hash)
puts "Connect completed"
#
c.disconnect


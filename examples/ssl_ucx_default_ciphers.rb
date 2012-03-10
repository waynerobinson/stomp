#
# Reference: https://github.com/morellon/stomp/wiki/extended-ssl-overview
#
require "rubygems"
require "stomp"

#
# If you use SSLParams, and need the _default_ Ruby ciphers, this is how. 
#
ssl_opts = Stomp::SSLParams.new(:use_ruby_ciphers => true)
#
# SSL Use Case: Using default Stomp ciphers
#
hash = { :hosts => [ 
      {:login => 'guest', :passcode => 'guest', :host => 'localhost', 
        :port => 61612, :ssl => ssl_opts},
      ]
    }
#
puts "Connect starts, SSL Use Case X"
c = Stomp::Connection.new(hash)
puts "Connect completed"
#
c.disconnect


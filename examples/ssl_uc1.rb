#
# Reference: https://github.com/morellon/stomp/wiki/extended-ssl-overview
#
require "rubygems"
require "stomp"
#
# SSL Use Case 1
#
hash = { :hosts => [ 
      {:login => 'guest', :passcode => 'guest', :host => 'localhost', :port => 61612, :ssl => true},
      ]
    }
#
puts "Connect starts, SSL Use Case 1"
c = Stomp::Connection.new(hash)
puts "Connect completed"
#
c.disconnect


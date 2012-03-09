#
# Reference: https://github.com/morellon/stomp/wiki/extended-ssl-overview
#
require "rubygems"
require "stomp"
#
# SSL Use Case 2
#
ssl_opts = Stomp::SSLParams.new(:key_file => "/home/gmallard/sslwork/twocas_tj/clientCA/ClientTJ.key",
  :cert_file => "/home/gmallard/sslwork/twocas_tj/clientCA/ClientTJ.crt")

#
hash = { :hosts => [ 
      {:login => 'guest', :passcode => 'guest', :host => 'localhost', :port => 61612, :ssl => ssl_opts},
      ]
    }
#
puts "Connect starts, SSL Use Case 2"
c = Stomp::Connection.new(hash)
puts "Connect completed"
#
# Expect a verify_result == 20
#
# This means: the client did not verify the peer's certificate, but the 
# handshake succeeds, and the connection is allowed.
#
puts "SSL Verify Result: #{ssl_opts.verify_result}"
puts "SSL Peer Certificate:\n#{ssl_opts.peer_cert}"
c.disconnect


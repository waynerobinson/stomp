#
# Reference: https://github.com/morellon/stomp/wiki/extended-ssl-overview
#
require "rubygems"
require "stomp"
#
# SSL Use Case 4
#
ssl_opts = Stomp::SSLParams.new(:key_file => "/home/gmallard/sslwork/client.key",
  :cert_file => "/home/gmallard/sslwork/client.crt",
  :ts_files => "/home/gmallard/sslwork/TestCA.crt")
#
hash = { :hosts => [ 
      {:login => 'guest', :passcode => 'guest', :host => 'localhost', :port => 61612, :ssl => ssl_opts},
      ]
    }
#
puts "Connect starts, SSL Use Case 4"
c = Stomp::Connection.new(hash)
puts "Connect completed"
#
# Expect a verify_result == 0
#
# This means: the client successfully verified the peer's certificate.
#
puts "SSL Verify Result: #{ssl_opts.verify_result}"
puts "SSL Peer Certificate:\n#{ssl_opts.peer_cert}"
c.disconnect


#
# Reference: https://github.com/morellon/stomp/wiki/extended-ssl-overview
#
require "rubygems"
require "stomp"
#
# SSL Use Case 3
#
ts_flist = []
ts_flist << "/home/gmallard/sslwork/twocas_tj/serverCA/ServerTJCA.crt"
ssl_opts = Stomp::SSLParams.new(:ts_files => ts_flist.join(","))
#
hash = { :hosts => [ 
      {:login => 'guest', :passcode => 'guest', :host => 'localhost', :port => 61612, :ssl => ssl_opts},
      ]
    }
#
puts "Connect starts, SSL Use Case 3"
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


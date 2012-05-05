#
# Reference: https://github.com/stompgem/stomp/wiki/extended-ssl-overview
#
require "rubygems"
require "stomp"
#
# SSL Use Case 3 - server *does* authenticate client, client does *not* authenticate server
#
# Subcase 3.A - Message broker configuration does *not* require client authentication
#
# - Expect connection success
# - Expect a verify result of 0 becuase the client did authenticate the
#   server's certificate.
#
# Subcase 3.B - Message broker configuration *does* require client authentication
#
# - Expect connection failure (broker must be sent a valid client certificate)
#
ts_flist = []
ts_flist << "/home/gmallard/sslwork/twocas_tj/serverCA/ServerTJCA.crt"
ssl_opts = Stomp::SSLParams.new(:ts_files => ts_flist.join(","))
#
hash = { :hosts => [ 
      {:login => 'guest', :passcode => 'guest', :host => 'localhost', :port => 61612, :ssl => ssl_opts},
      ],
    :reliable => false, # YMMV, to test this in a sane manner
    }
#
puts "Connect starts, SSL Use Case 3"
c = Stomp::Connection.new(hash)
puts "Connect completed"
puts "SSL Verify Result: #{ssl_opts.verify_result}"
# puts "SSL Peer Certificate:\n#{ssl_opts.peer_cert}"
c.disconnect


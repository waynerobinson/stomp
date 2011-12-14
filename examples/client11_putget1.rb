#
# The current require dance for different Ruby versions.
# Change this to suit your requirements.
#
if Kernel.respond_to?(:require_relative)
  require_relative("./stomp11_common")
else
  $LOAD_PATH << File.dirname(__FILE__)
  require "stomp11_common"
end
include Stomp11Common
#
# Stomp 1.1 Client Pitter/Getter Example 1
# ========================================
#
#
client_hdrs = {"accept-version" => "1.1",    # Demand a 1.1 connection (use a CSV list if you will consider multiple versions)
      "host" => virt_host,                 # The 1.1 vhost (could be different than connection host)
    }                                      # No heartbeats here:  there will be none for this connection
#
client_hash = { :hosts => [ 
      {:login => login, :passcode => passcode, :host => host, :port => port},
      ],
      :connect_headers => client_hdrs,
    }
#
client = Stomp::Client.new(client_hash)
puts "Connection complete"
#
raise "Unexpected protocol level" if client.protocol() != Stomp::SPL_11
#
client.close   # Business as usual, just like 1.0
puts "Disclientect complete"




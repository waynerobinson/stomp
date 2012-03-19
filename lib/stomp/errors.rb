# -*- encoding: utf-8 -*-

module Stomp
  module Error
    class InvalidFormat < RuntimeError
      def message
        "Invalid message - invalid format"
      end
    end

    class InvalidServerCommand < RuntimeError
      def message
        "Invalid command from server"
      end
    end

    class InvalidMessageLength < RuntimeError
      def message
        "Invalid content length received"
      end
    end

    class PacketParsingTimeout < RuntimeError
      def message
        "Packet parsing timeout"
      end
    end

    class SocketOpenTimeout < RuntimeError
      def message
        "Socket open timeout"
      end
    end

    class NoCurrentConnection < RuntimeError
      def message
        "no current connection exists"
      end
    end
    
    class MaxReconnectAttempts < RuntimeError
      def message
        "Maximum number of reconnection attempts reached"
      end
    end
    
    class DuplicateSubscription < RuntimeError
      def message
        "duplicate subscriptions are disallowed"
      end
    end
    
    class ProtocolErrorConnect < RuntimeError
      def message
        "protocol error on CONNECT"
      end
    end
    
    class UnsupportedProtocolError < RuntimeError
      def message
        "unsupported protocol level(s)"
      end
    end
    
    class InvalidHeartBeatHeaderError < RuntimeError
      def message
        "heart-beat header value is malformed"
      end
    end

    class SubscriptionRequiredError < RuntimeError
      def message
        "a valid subscription id header is required"
      end
    end

    class UTF8ValidationError < RuntimeError
      def message
        "header is invalid UTF8"
      end
    end

    class MessageIDRequiredError < RuntimeError
      def message
        "a valid message id is required for ACK/NACK"
      end
    end

    class SSLClientParamsError < RuntimeError
      def message
        "certificate and key files are both required"
      end
    end

    class StompServerError < RuntimeError
      def message
        "Connected, header read is nil, is this really a Stomp Server?"
      end
    end

    class SSLNoKeyFileError < RuntimeError
      def message
        "client key file does not exist"
      end
    end

    class SSLUnreadableKeyFileError < RuntimeError
      def message
        "client key file can not be read"
      end
    end

    class SSLNoCertFileError < RuntimeError
      def message
        "client cert file does not exist"
      end
    end

    class SSLUnreadableCertFileError < RuntimeError
      def message
        "client cert file can not be read"
      end
    end

    class SSLNoTruststoreFileError < RuntimeError
      def message
        "a client truststore file does not exist"
      end
    end

    class SSLUnreadableTruststoreFileError < RuntimeError
      def message
        "a client truststore file can not be read"
      end
    end

    class LoggerConnectionError < RuntimeError
    end

  end # module Error
end # module Stomp


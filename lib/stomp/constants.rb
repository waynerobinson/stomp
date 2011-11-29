# -*- encoding: utf-8 -*-

module Stomp

	# Client side
	CMD_CONNECT     = "CONNECT"
	CMD_STOMP       = "STOMP"
	CMD_DISCONNECT  = "DISCONNECT"
	CMD_SEND        = "SEND"
	CMD_SUBSCRIBE   = "SUBSCRIBE"
	CMD_UNSUBSCRIBE = "UNSUBSCRIBE"
	CMD_ACK         = "ACK"
	CMD_NACK        = "NACK"
	CMD_BEGIN       = "BEGIN"
	CMD_COMMIT      = "COMMIT"
	CMD_ABORT       = "ABORT"

	# Server side
	CMD_CONNECTED = "CONNECTED"
	CMD_MESSAGE   = "MESSAGE"
	CMD_RECEIPT   = "RECEIPT"
	CMD_ERROR     = "ERROR"

	# Protocols
	SPL_10 = "1.0"
	SPL_11 = "1.1"

  # To be: No 1.1 yet
  SUPPORTED = [SPL_10, SPL_11]

  # 1.9 Encoding Name
  UTF8 = "UTF-8"

end

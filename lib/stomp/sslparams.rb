# -*- encoding: utf-8 -*-

module Stomp
  #
  # == Purpose
  #
  # Parameters for STOMP ssl connections.
  #
  class SSLParams
    # The trust store file.  Normally the certificate of the CA that signed
    # the server's certificate.
    attr_accessor :ts_file
    # The client certificate file.
    attr_accessor :cert_file
    # The client private key file.
    attr_accessor :key_file
    # SSL Connect Verify Result.  The result of the handshake.
    attr_accessor :verify_result
    # The certificate of the connection peer (the server), received during
    # the handshake.
    attr_accessor :peer_cert
    #
    def initialize(opts={})

      # Server authentication parameters
      @ts_file = opts[:ts_file]   # A trust store file, normally a CA's cert

      # Client authentication parameters
      @cert_file = opts[:cert_file]         # Client cert
      @key_file = opts[:key_file]           # Client key
      #
      raise Stomp::Error::SSLClientParamsError if @cert_file.nil? && !@key_file.nil?
      raise Stomp::Error::SSLClientParamsError if !@cert_file.nil? && @key_file.nil?
    end
  end # of class SSLParams

end # of module Stomp


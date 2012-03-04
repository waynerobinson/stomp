# -*- encoding: utf-8 -*-

$:.unshift(File.dirname(__FILE__))

require 'test_helper'

class TestSSL < Test::Unit::TestCase
  include TestBase
  
  def setup
    @conn = get_ssl_connection()
  end

  def teardown
    @conn.disconnect if @conn.open? # allow tests to disconnect
  end
  #
  def test_ssl_0000
    assert @conn.open?
  end

  #
  def test_ssl_0010
    ssl_params = Stomp::SSLParams.new
    assert ssl_params.ts_files.nil?
    assert ssl_params.cert_file.nil?
    assert ssl_params.key_file.nil?
  end

  #
  def test_ssl_0020
    assert_raise(Stomp::Error::SSLClientParamsError) {
      ssl_parms = Stomp::SSLParams.new(:cert_file => "dummy1")
    }
    assert_raise(Stomp::Error::SSLClientParamsError) {
      ssl_parms = Stomp::SSLParams.new(:key_file => "dummy2")
    }
    assert_nothing_raised {
      ssl_parms = Stomp::SSLParams.new(:cert_file => "dummy1", :key_file => "dummy2")
    }
    assert_nothing_raised {
      ssl_parms = Stomp::SSLParams.new(:ts_files => "dummyts1")
    }
    assert_nothing_raised {
      ssl_parms = Stomp::SSLParams.new(:ts_files => "dummyts1", :cert_file => "dummy1", :key_file => "dummy2")
    }
  end

  #
end if ENV['STOMP_TESTSSL']


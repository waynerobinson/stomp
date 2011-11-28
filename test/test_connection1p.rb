# -*- encoding: utf-8 -*-

$:.unshift(File.dirname(__FILE__))

require 'test_helper'

class TestStomp < Test::Unit::TestCase
  include TestBase
  
  def setup
    @conn = get_connection()
  end

  def teardown
    @conn.disconnect if @conn.open? # allow tests to disconnect
  end
  #
  def test_conn_1p_0000
    assert @conn.open?
  end
  #
  def test_conn_1p_0010
    #
    cha = {:host => "localhost"}
    assert_raise Stomp::Error::ProtocolErrorConnect do
      conn = Stomp::Connection.open(user, passcode, host, port, false, 5, cha)
    end    
    #
    chb = {"accept-version" => "1.0"}
    assert_raise Stomp::Error::ProtocolErrorConnect do
      conn = Stomp::Connection.open(user, passcode, host, port, false, 5, chb)
    end    
  end
  #
  def test_conn_1p_0020
    #
    cha = {:host => "localhost", "accept-version" => "1.0"}
    cha[:host] = "/" if ENV['STOMP_RABBIT']
    conn = nil
    assert_nothing_raised do
      conn = Stomp::Connection.open(user, passcode, host, port, false, 5, cha)
      conn.disconnect
    end
    assert_equal conn.protocol, Stomp::SPL_10
  end
  #
  def test_conn_1p_0030
    #
    cha = {:host => "localhost", "accept-version" => "1.1"}
    cha[:host] = "/" if ENV['STOMP_RABBIT']
    conn = nil
    assert_nothing_raised do
      conn = Stomp::Connection.open(user, passcode, host, port, false, 5, cha)
      conn.disconnect
    end
    assert_equal conn.protocol, Stomp::SPL_11
  end
  #
  def test_conn_1p_0040
    #
    cha = {:host => "localhost", "accept-version" => "1.1"}
    cha[:host] = "/" if ENV['STOMP_RABBIT']
    cha["heart-beat"] = "0,0" # No heartbeats
    conn = nil
    assert_nothing_raised do
      conn = Stomp::Connection.open(user, passcode, host, port, false, 5, cha)
      conn.disconnect
    end
    assert_equal conn.protocol, Stomp::SPL_11
  end
  #

  def test_conn_1p_0050
    #
    cha = {:host => "localhost", "accept-version" => "1.1"}
    cha[:host] = "/" if ENV['STOMP_RABBIT']
    cha["heart-beat"] = "10,10,20" # Bad header Heartbeats
    conn = nil
    assert_raise Stomp::Error::InvalidHeartBeatHeaderError do
      conn = Stomp::Connection.open(user, passcode, host, port, false, 5, cha)
    end
  end
  #
  def test_conn_11h_0060
    #
    cha = {:host => "localhost", "accept-version" => "1.1"}
    cha[:host] = "/" if ENV['STOMP_RABBIT']
    cha["heart-beat"] = "a,10" # Bad header Heartbeats
    conn = nil
    assert_raise Stomp::Error::InvalidHeartBeatHeaderError do
      conn = Stomp::Connection.open(user, passcode, host, port, false, 5, cha)
    end
  end
  #
  def test_conn_1p_0070
    #
    cha = {:host => "localhost", "accept-version" => "1.1"}
    cha[:host] = "/" if ENV['STOMP_RABBIT']
    cha["heart-beat"] = "500,1000" # Valid heart beat headers
    conn = nil
    assert_nothing_raised do
      conn = Stomp::Connection.open(user, passcode, host, port, false, 5, cha)
      conn.disconnect
    end
  end

  #
  def test_conn_1p_0080
    #
    cha = {:host => "localhost", "accept-version" => "1.1"}
    cha[:host] = "/" if ENV['STOMP_RABBIT']
    cha["heart-beat"] = "5000,0" # Valid heart beat headers, send only
    conn = nil
    assert_nothing_raised do
      conn = Stomp::Connection.open(user, passcode, host, port, false, 5, cha)
      sleep 65
      conn.disconnect
    end
  end if ENV['STOMP_HB11LONG']

  #
  def test_conn_1p_0090
    #
    cha = {:host => "localhost", "accept-version" => "1.1"}
    cha[:host] = "/" if ENV['STOMP_RABBIT']
    cha["heart-beat"] = "0,10000" # Valid heart beat headers, receive only
    conn = nil
    assert_nothing_raised do
      conn = Stomp::Connection.open(user, passcode, host, port, false, 5, cha)
#      m = conn.receive # This will hang forever .....
      sleep 65
      conn.disconnect
    end
  end if ENV['STOMP_HB11LONG']

  #
  def test_conn_1p_0100
    #
    cha = {:host => "localhost", "accept-version" => "1.1"}
    cha[:host] = "/" if ENV['STOMP_RABBIT']
    cha["heart-beat"] = "5000,10000" # Valid heart beat headers, send and receive
    conn = nil
    assert_nothing_raised do
      conn = Stomp::Connection.open(user, passcode, host, port, false, 5, cha)
#      m = conn.receive # This will hang forever .....
      sleep 65
      conn.disconnect
    end
  end if ENV['STOMP_HB11LONG']

end if ENV['STOMP_TEST11']


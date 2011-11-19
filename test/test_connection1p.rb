$:.unshift(File.dirname(__FILE__))

require 'test_helper'

class TestStomp < Test::Unit::TestCase
  include TestBase
  
  def setup
  end

  def teardown
  end
  #
  def test_conn_11a
    ch = {}
    assert_nothing_raised {
      conn = Stomp::Connection.open(user, passcode, host, port, false, 5, ch)
      conn.disconnect
    }  
  end
  #
  def test_conn_11b
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
  def test_conn_11c
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
  def test_conn_11s
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
  def test_conn_11hb00
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
  def test_conn_11hb_bad1
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
  def test_conn_11hb_bad2
    #
    cha = {:host => "localhost", "accept-version" => "1.1"}
    cha[:host] = "/" if ENV['STOMP_RABBIT']
    cha["heart-beat"] = "a,10" # Bad header Heartbeats
    conn = nil
    assert_raise Stomp::Error::InvalidHeartBeatHeaderError do
      conn = Stomp::Connection.open(user, passcode, host, port, false, 5, cha)
    end
  end
  # This should fail when heart-beats are fully implemented.
  def test_conn_11hb_bad_nosupp
    #
    cha = {:host => "localhost", "accept-version" => "1.1"}
    cha[:host] = "/" if ENV['STOMP_RABBIT']
    cha["heart-beat"] = "10,10" # Heartbeats
    conn = nil
    assert_raise Stomp::Error::HeartbeatsUnsupportedError do
      conn = Stomp::Connection.open(user, passcode, host, port, false, 5, cha)
    end
  end
end if ENV['STOMP_TEST11']


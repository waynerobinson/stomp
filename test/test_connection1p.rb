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
    return unless ENV['STOMP_TEST11']
    ch = {}
    assert_nothing_raised {
      conn = Stomp::Connection.open(user, passcode, host, port, false, 5, ch)
      conn.disconnect
    }  
  end
  #
  def test_conn_11b
    return unless ENV['STOMP_TEST11']
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
    return unless ENV['STOMP_TEST11']
    #
    cha = {:host => "localhost", "accept-version" => "1.0"}
    conn = nil
    assert_nothing_raised do
      conn = Stomp::Connection.open(user, passcode, host, port, false, 5, cha)
      conn.disconnect
    end
    assert_equal conn.protocol, Stomp::SPL_10
  end
  #
  def test_conn_11s
    return unless ENV['STOMP_TEST11']
    #
    cha = {:host => "localhost", "accept-version" => "1.1"}
    conn = nil
    assert_nothing_raised do
      conn = Stomp::Connection.open(user, passcode, host, port, false, 5, cha)
      conn.disconnect
    end
    assert_equal conn.protocol, Stomp::SPL_11
  end
end


# -*- encoding: utf-8 -*-

$:.unshift(File.dirname(__FILE__))

require 'test_helper'

class TestConnection < Test::Unit::TestCase
  include TestBase
  
  def setup
    @conn = get_connection()
    # Data for multi_thread tests
    @max_threads = 20
    @max_msgs = 100
  end

  def teardown
    @conn.disconnect if @conn.open? # allow tests to disconnect
  end

  def test_connection_exists
    assert_not_nil @conn
  end

  def test_poll_async
    @conn.subscribe("/queue/do.not.put.messages.on.this.queue", :id => "a.no.messages.queue")
    # If the test 'hangs' here, Connection#poll is broken.
    m = @conn.poll
    assert m.nil?
  end

  def test_no_length
    conn_subscribe make_destination
    #
    @conn.publish make_destination, "test_stomp#test_no_length",
      { :suppress_content_length => true }
    msg = @conn.receive
    assert_equal "test_stomp#test_no_length", msg.body
    #
    @conn.publish make_destination, "test_stomp#test_\000_length",
      { :suppress_content_length => true }
    msg2 = @conn.receive
    if @conn.protocol == Stomp::SPL_10
      assert_equal "test_stomp#test_", msg2.body
    else
      assert_equal "test_stomp#test_\000_length", msg2.body
    end
  end unless ENV['STOMP_RABBIT']

  def test_explicit_receive
    conn_subscribe make_destination
    @conn.publish make_destination, "test_stomp#test_explicit_receive"
    msg = @conn.receive
    assert_equal "test_stomp#test_explicit_receive", msg.body
  end

  def test_receipt
    conn_subscribe make_destination, :receipt => "abc"
    msg = @conn.receive
    assert_equal "abc", msg.headers['receipt-id']
  end

  def test_disconnect_receipt
    @conn.disconnect :receipt => "abc123"
    assert_nothing_raised {
      assert_not_nil(@conn.disconnect_receipt, "should have a receipt")
      assert_equal(@conn.disconnect_receipt.headers['receipt-id'],
        "abc123", "receipt sent and received should match")
    }
  end

  def test_client_ack_with_symbol
    if @conn.protocol == Stomp::SPL_10
      @conn.subscribe make_destination, :ack => :client
    else
      sid = @conn.uuid()
      @conn.subscribe make_destination, :ack => :client, :id => sid
    end
    @conn.publish make_destination, "test_stomp#test_client_ack_with_symbol"
    msg = @conn.receive
    assert_nothing_raised {
      if @conn.protocol == Stomp::SPL_10
        @conn.ack msg.headers['message-id']
      else
        @conn.ack msg.headers['message-id'], :subscription => sid
      end
    }
  end

  def test_embedded_null
    conn_subscribe make_destination
    @conn.publish make_destination, "a\0"
    msg = @conn.receive
    assert_equal "a\0" , msg.body
  end

  def test_connection_open?
    assert_equal true , @conn.open?
    @conn.disconnect
    assert_equal false, @conn.open?
  end

  def test_connection_closed?
    assert_equal false, @conn.closed?
    @conn.disconnect
    assert_equal true, @conn.closed?
  end

  def test_closed_checks_conn
    @conn.disconnect
    #
    assert_raise Stomp::Error::NoCurrentConnection do
      @conn.ack("dummy_data")
    end
    #
    assert_raise Stomp::Error::NoCurrentConnection do
      @conn.begin("dummy_data")
    end
    #
    assert_raise Stomp::Error::NoCurrentConnection do
      @conn.commit("dummy_data")
    end
    #
    assert_raise Stomp::Error::NoCurrentConnection do
      @conn.abort("dummy_data")
    end
    #
    assert_raise Stomp::Error::NoCurrentConnection do
      conn_subscribe("dummy_data")
    end
    #
    assert_raise Stomp::Error::NoCurrentConnection do
      @conn.unsubscribe("dummy_data")
    end
    #
    assert_raise Stomp::Error::NoCurrentConnection do
      @conn.publish("dummy_data","dummy_data")
    end
    #
    assert_raise Stomp::Error::NoCurrentConnection do
      @conn.unreceive("dummy_data")
    end
    #
    assert_raise Stomp::Error::NoCurrentConnection do
      @conn.disconnect("dummy_data")
    end
    #
    assert_raise Stomp::Error::NoCurrentConnection do
      m = @conn.receive
    end
    #
    assert_raise Stomp::Error::NoCurrentConnection do
      m = @conn.poll
    end
  end

  def test_response_is_instance_of_message_class
    conn_subscribe make_destination
    @conn.publish make_destination, "a\0"
    msg = @conn.receive
    assert_instance_of Stomp::Message , msg
  end

  def test_message_to_s
    conn_subscribe make_destination
    @conn.publish make_destination, "a\0"
    msg = @conn.receive
    assert_match /^<Stomp::Message headers=/ , msg.to_s
  end
  
  def test_connection_frame
  	assert_not_nil @conn.connection_frame
  end
  
  def test_messages_with_multipleLine_ends
    conn_subscribe make_destination
    @conn.publish make_destination, "a\n\n"
    @conn.publish make_destination, "b\n\na\n\n"
    
    msg_a = @conn.receive
    msg_b = @conn.receive

    assert_equal "a\n\n", msg_a.body
    assert_equal "b\n\na\n\n", msg_b.body
  end

  def test_publish_two_messages
    conn_subscribe make_destination
    @conn.publish make_destination, "a\0"
    @conn.publish make_destination, "b\0"
    msg_a = @conn.receive
    msg_b = @conn.receive

    assert_equal "a\0", msg_a.body
    assert_equal "b\0", msg_b.body
  end

  def test_thread_hang_one
    received = nil
    Thread.new(@conn) do |amq|
        while true
            received = amq.receive
        end
    end
    #
    conn_subscribe( make_destination )
    message = Time.now.to_s
    @conn.publish(make_destination, message)
    sleep 1
    assert_not_nil received
    assert_equal message, received.body
  end

  def test_thread_poll_one
    received = nil
    max_sleep = (RUBY_VERSION =~ /1\.8/) ? 10 : 1
    Thread.new(@conn) do |amq|
        while true
          received = amq.poll
          # One message is needed
          Thread.exit if received
          sleep max_sleep
        end
    end
    #
    conn_subscribe( make_destination )
    message = Time.now.to_s
    @conn.publish(make_destination, message)
    sleep max_sleep+1
    assert_not_nil received
    assert_equal message, received.body
  end

  def test_multi_thread_receive
    lock = Mutex.new
    msg_ctr = 0
    dest = make_destination
    #
    1.upto(@max_threads) do |tnum|
      Thread.new(@conn) do |amq|
        while true
          received = amq.receive
          lock.synchronize do
            msg_ctr += 1
          end
          # Simulate message processing
          sleep 0.05
        end
      end
    end
    #
    conn_subscribe( dest )
    1.upto(@max_msgs) do |mnum|
      msg = Time.now.to_s + " #{mnum}"
      @conn.publish(dest, msg)
    end
    #
    max_sleep = (RUBY_VERSION =~ /1\.8/) ? 30 : 5
    max_sleep = 30 if RUBY_ENGINE =~ /mingw/
    sleep_incr = 0.10
    total_slept = 0
    while true
      break if @max_msgs == msg_ctr
      total_slept += sleep_incr
      break if total_slept > max_sleep
      sleep sleep_incr
    end
    assert_equal @max_msgs, msg_ctr
  end unless RUBY_ENGINE =~ /jruby/

  def test_multi_thread_poll
    #
    lock = Mutex.new
    msg_ctr = 0
    dest = make_destination
    #
    1.upto(@max_threads) do |tnum|
      Thread.new(@conn) do |amq|
        while true
          received = amq.poll
          if received
            lock.synchronize do
              msg_ctr += 1
            end
            # Simulate message processing
            sleep 0.05
          else
            # Wait a bit for more work
            sleep 0.05
          end
        end
      end
    end
    #
    conn_subscribe( dest )
    1.upto(@max_msgs) do |mnum|
      msg = Time.now.to_s + " #{mnum}"
      @conn.publish(dest, msg)
    end
    #
    max_sleep = (RUBY_VERSION =~ /1\.8\.6/) ? 30 : 5
    max_sleep = 30 if RUBY_ENGINE =~ /mingw/
    sleep_incr = 0.10
    total_slept = 0
    while true
      break if @max_msgs == msg_ctr
      total_slept += sleep_incr
      break if total_slept > max_sleep
      sleep sleep_incr
    end
    assert_equal @max_msgs, msg_ctr
  end unless RUBY_ENGINE =~ /jruby/

  def test_nil_body
    dest = make_destination
    assert_nothing_raised {
      @conn.publish dest, nil
    }
    conn_subscribe dest
    msg = @conn.receive
    assert_equal "", msg.body    
  end

  def test_transaction
    conn_subscribe make_destination

    @conn.begin "txA"
    @conn.publish make_destination, "txn message", 'transaction' => "txA"

    @conn.publish make_destination, "first message"

    msg = @conn.receive
    assert_equal "first message", msg.body

    @conn.commit "txA"
    msg = @conn.receive
    assert_equal "txn message", msg.body
  end

  def test_duplicate_subscription
    @conn.disconnect # not reliable
    @conn = Stomp::Connection.open(user, passcode, host, port, true) # reliable
    dest = make_destination
    conn_subscribe dest
    #
    assert_raise Stomp::Error::DuplicateSubscription do
      conn_subscribe dest
    end
  end

  def test_nil_connparms
    @conn.disconnect
    #
    assert_nothing_raised do
      @conn = Stomp::Connection.open(user, passcode, host, port, false, 5, nil)
    end
  end

  def test_nack11p_0010
    if @conn.protocol == Stomp::SPL_10
      assert_raise Stomp::Error::UnsupportedProtocolError do
        @conn.nack "dummy msg-id"
      end
    else
      sid = @conn.uuid()
      dest = make_destination
      @conn.subscribe dest, :ack => :client, :id => sid
      smsg = "test_stomp#test_nack01: #{Time.now.to_f}"
      @conn.publish make_destination, smsg
      msg = @conn.receive
      assert_equal smsg, msg.body
      assert_nothing_raised {
        @conn.nack msg.headers["message-id"], :subscription => sid
        sleep 0.05 # Give racy brokers a chance to handle the last nack before unsubscribe
        @conn.unsubscribe dest, :id => sid
      }
      # phase 2
      teardown()
      setup()
      sid = @conn.uuid()
      @conn.subscribe dest, :ack => :auto, :id => sid
      msg2 = @conn.receive
      assert_equal smsg, msg2.body
    end
  end

end


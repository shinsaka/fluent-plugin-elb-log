require_relative '../helper'

class Elb_LogInputTest < Test::Unit::TestCase

  def setup
    Fluent::Test.setup
  end

  DEFAULT_CONFIG = {
    :access_key_id     => 'dummy_access_key_id',
    :secret_access_key => 'dummy_secret_access_key',
    :s3_endpoint       => 's3-ap-northeast-1.amazonaws.com',
    :s3_bucketname     => 'bummy_bucket',
    :s3_prefix         => 'test',
    :timestamp_file    => 'elb_last_at.dat',
    :refresh_interval  => 300
  }

  def parse_config(conf = {})
    ''.tap{|s| conf.each { |k, v| s << "#{k} #{v}\n" } }
  end

  def create_driver(conf = DEFAULT_CONFIG)
    Fluent::Test::InputTestDriver.new(Fluent::Elb_LogInput).configure(parse_config conf)
  end

  def iam_info
    stub_request(:get, "http://169.254.169.254/latest/meta-data/iam/info")
  end

  def use_iam_role
    iam_info.to_return(:status => [200, 'OK'])
  end

  def not_use_iam_role
    iam_info.to_return(:status => [404, 'Not Found'])
  end

  def test_confiture_default
    use_iam_role
    assert_nothing_raised { driver = create_driver }

    exception = assert_raise(Fluent::ConfigError) {
      conf = DEFAULT_CONFIG.clone
      conf.delete(:s3_bucketname)
      driver = create_driver(conf)
    }
    assert_equal('s3_bucketname is required', exception.message)

    exception = assert_raise(Fluent::ConfigError) {
      conf = DEFAULT_CONFIG.clone
      conf.delete(:timestamp_file)
      driver = create_driver(conf)
    }
    assert_equal('timestamp_file is required', exception.message)
  end

  def test_configure_in_EC2_with_IAM_role
    use_iam_role
    conf = DEFAULT_CONFIG.clone
    conf.delete(:access_key_id)
    conf.delete(:secret_access_key)
    assert_nothing_raised { driver = create_driver(conf) }
  end

  def test_configure_in_EC2_without_IAM_role
    not_use_iam_role
    exception = assert_raise(Fluent::ConfigError) {
      conf = DEFAULT_CONFIG.clone
      conf.delete(:access_key_id)
      driver = create_driver(conf)
    }
    assert_equal('access_key_id is required', exception.message)

    exception = assert_raise(Fluent::ConfigError) {
      conf = DEFAULT_CONFIG.clone
      conf.delete(:secret_access_key)
      driver = create_driver(conf)
    }
    assert_equal('secret_access_key is required', exception.message)
  end

  def test_configure_outside_EC2
    iam_info.to_timeout

    assert_nothing_raised { driver = create_driver }
    exception = assert_raise(Fluent::ConfigError) {
      conf = DEFAULT_CONFIG.clone
      conf.delete(:access_key_id)
      driver = create_driver(conf)
    }
    assert_equal('access_key_id is required', exception.message)

    exception = assert_raise(Fluent::ConfigError) {
      conf = DEFAULT_CONFIG.clone
      conf.delete(:secret_access_key)
      driver = create_driver(conf)
    }
    assert_equal('secret_access_key is required', exception.message)
  end

end

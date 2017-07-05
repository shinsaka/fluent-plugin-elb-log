require 'bundler/setup'
require 'test/unit'
require 'webmock/test_unit'
require 'simplecov'

SimpleCov.start

$LOAD_PATH.unshift(File.join(__dir__, '..', 'lib'))
$LOAD_PATH.unshift(__dir__)
require 'fluent/test'
require 'fluent/test/helpers'
require 'fluent/test/driver/input'
require 'fluent/plugin/in_elb_log'

class Test::Unit::TestCase
  include Fluent::Test::Helpers
  extend Fluent::Test::Helpers
end

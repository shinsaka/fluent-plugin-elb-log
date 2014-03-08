class Fluent::Elb_LogInput < Fluent::Input
  Fluent::Plugin.register_input('elb_log', self)

  config_param :access_key_id, :string, :default => nil
  config_param :secret_access_key, :string, :default => nil
  config_param :s3_bucketname, :string, :default => nil
  config_param :s3_endpoint, :string, :default => 's3.amazon.com'
  config_param :timestamp_file, :string, :default => nil

  def configure(conf)
    super
    require 'aws-sdk'
    raise Fluent::ConfigError.new("access_key_id is required") unless @access_key_id
    raise Fluent::ConfigError.new("secret_access_key is required") unless @secret_access_key
    raise Fluent::ConfigError.new("s3_bucketname is required") unless @s3_bucketname
    raise Fluent::ConfigError.new("timestamp_file is required") unless @timestamp_file
  end

  def start
    super

    init_s3bucket()

    @timestamp_file = File.open(@timestamp_file, File::RDWR|File::CREAT)
    @timestamp_file.sync = true

    @loop = Coolio::Loop.new
    timer_trigger = TimerWatcher.new(60, true, &method(:on_notify))
    timer_trigger 
    @thread = Thread.new(&method(:run))
  end

  def shutdown
    super
    @loop.stop
    @thread.join
    @timestamp_file.close
  end

  private

  def init_s3bucket
    @bucket = AWS::S3.new(
      access_key_id: @aws_access_key_id,
      secret_access_key: @secret_access_key
    ).buckets[@aws_s3_bucketname]
  end

  def run
    @loop.run
  rescue
    log.error "unexpected error", :error=>$!.to_s
    log.error_backtrace
  end

  class TimerWatcher < Coolio::TimerWatcher
    def initialize(interval, repeat, &callback)
      @callback = callback
      super(interval, repeat)
    end

    def on_timer
      @callback.call
    rescue
      @log.error $!.to_s
      @log.error_backtrace
    end
  end
end

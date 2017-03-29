require 'fluent/input'

class Fluent::Elb_LogInput < Fluent::Input
  Fluent::Plugin.register_input('elb_log', self)

  LOGFILE_REGEXP = /^((?<prefix>.+?)\/|)AWSLogs\/(?<account_id>[0-9]{12})\/elasticloadbalancing\/(?<region>.+?)\/(?<logfile_date>[0-9]{4}\/[0-9]{2}\/[0-9]{2})\/[0-9]{12}_elasticloadbalancing_.+?_(?<logfile_elb_name>[^_]+)_(?<elb_timestamp>[0-9]{8}T[0-9]{4}Z)_(?<elb_ip_address>.+?)_(?<logfile_hash>.+)\.log$/
  ACCESSLOG_REGEXP = /^(?<time>\d{4}-\d{2}-\d{2}T\d{2}\:\d{2}\:\d{2}\.\d{6}Z) (?<elb>.+?) (?<client>[^ ]+)\:(?<client_port>.+?) (?<backend>.+?)(\:(?<backend_port>.+?))? (?<request_processing_time>.+?) (?<backend_processing_time>.+?) (?<response_processing_time>.+?) (?<elb_status_code>.+?) (?<backend_status_code>.+?) (?<received_bytes>.+?) (?<sent_bytes>.+?) \"(?<request_method>.+?) (?<request_uri>.+?) (?<request_protocol>.+?)\"( \"(?<user_agent>.*?)\" (?<ssl_cipher>.+?) (?<ssl_protocol>.+)(| (?<option3>.*)))?/

  # To support log_level option implemented by Fluentd v0.10.43
  unless method_defined?(:log)
    define_method("log") { $log }
  end

  # Define `router` method to support v0.10.57 or earlier
  unless method_defined?(:router)
    define_method("router") { Fluent::Engine }
  end

  config_param :access_key_id, :string, default: nil, secret: true
  config_param :secret_access_key, :string, default: nil, secret: true
  config_param :region, :string, default: nil
  config_param :s3_bucketname, :string, default: nil
  config_param :s3_prefix, :string, default: nil
  config_param :tag, :string, default: 'elb.access'
  config_param :timestamp_file, :string, default: nil
  config_param :refresh_interval, :integer, default: 300
  config_param :buf_file, :string, default: './fluentd_elb_log_buf_file'
  config_param :http_proxy, :string, default: nil
  config_param :start_time, :string, default: nil

  def configure(conf)
    super
    require 'aws-sdk'

    raise Fluent::ConfigError.new("region is required") unless @region
    if !has_iam_role?
      raise Fluent::ConfigError.new("access_key_id is required") if @access_key_id.nil?
      raise Fluent::ConfigError.new("secret_access_key is required") if @secret_access_key.nil?
    end
    raise Fluent::ConfigError.new("s3_bucketname is required") unless @s3_bucketname
    raise Fluent::ConfigError.new("timestamp_file is required") unless @timestamp_file
  end

  def start
    super

    # files touch
    File.open(@timestamp_file, File::RDWR|File::CREAT).close
    File.open(@buf_file, File::RDWR|File::CREAT).close

    raise StandardError.new("s3 bucket not found #{@s3_bucketname}") unless s3bucket_is_ok()

    @loop = Coolio::Loop.new
    timer_trigger = TimerWatcher.new(@refresh_interval, true, &method(:input))
    timer_trigger.attach(@loop)
    @thread = Thread.new(&method(:run))
  end

  def shutdown
    super
    @loop.stop
    @thread.join
  end

  private

  def has_iam_role?
    begin
      ec2 = Aws::EC2::Client.new(region: @region)
      !ec2.config.credentials.nil?
    rescue => e
      log.warn "EC2 Client error occurred: #{e.message}"
    end
  end

  def get_timestamp_file
    require 'time'
    begin
      # get timestamp last proc
      start_time = @start_time ? Time.parse(@start_time).utc : Time.at(0)
      timestamp = start_time.to_i
      log.debug "timestamp file #{@timestamp_file} read"
      File.open(@timestamp_file, File::RDONLY) do |file|
        timestamp = file.read.to_i if file.size > 0
      end
      log.debug "timestamp start at:" + Time.at(timestamp).to_s
      return timestamp
    rescue => e
      log.warn "timestamp file get and parse error occurred: #{e.message}"
    end
  end

  def put_timestamp_file(timestamp)
    begin
      log.debug "timestamp file #{@timestamp_file} write"
      File.open(@timestamp_file, File::WRONLY|File::CREAT|File::TRUNC) do |file|
        file.puts timestamp.to_s
      end
    rescue => e
      log.warn "timestamp file get and parse error occurred: #{e.message}"
    end
  end

  def s3_client
    begin
      options = {
        region: @region,
      }
      if @access_key_id && @secret_access_key
        options[:access_key_id] = @access_key_id
        options[:secret_access_key] = @secret_access_key
      end
      if @http_proxy
        options[:http_proxy] = @http_proxy
      end
      log.debug "S3 client connect"
      Aws::S3::Client.new(options)
    rescue => e
      log.warn "S3 Client error occurred: #{e.message}"
    end
  end

  def s3bucket_is_ok
    begin
      log.debug "search bucket #{@s3_bucketname}"

      s3_client.list_buckets.buckets.any? do |bucket|
        bucket.name == @s3_bucketname
      end
    rescue => e
      log.warn "S3 Client error occurred: #{e.message}"
    end
  end

  def input
    log.debug "start"

    timestamp = get_timestamp_file()

    object_keys = get_object_keys(timestamp)
    object_keys = sort_object_key(object_keys)

    log.info "processing #{object_keys.count} object(s)."

    object_keys.each do |object_key|
      record_common = {
        "account_id" => object_key[:account_id],
        "region" => object_key[:region],
        "logfile_date" => object_key[:logfile_date],
        "logfile_elb_name" => object_key[:logfile_elb_name],
        "elb_ip_address" => object_key[:elb_ip_address],
        "logfile_hash" => object_key[:logfile_hash],
        "elb_timestamp" => object_key[:elb_timestamp],
        "key" => object_key[:key],
        "prefix" => object_key[:prefix],
        "elb_timestamp_unixtime" => object_key[:elb_timestamp_unixtime],
      }

      get_file_from_s3(object_key[:key])
      emit_lines_from_buffer_file(record_common)

      put_timestamp_file(object_key[:elb_timestamp_unixtime])
    end
  end

  def get_object_keys(timestamp)
    # get values from object file name
    begin
      object_keys = []

      objects = s3_client.list_objects(
        bucket: @s3_bucketname,
        max_keys: 100,
        prefix: @s3_prefix,
      )
  
      objects.each do |object|
        object.contents.each do |content|
          matches = LOGFILE_REGEXP.match(content.key)
          next unless matches

          # snip old items
          elb_timestamp_unixtime = Time.parse(matches[:elb_timestamp]).to_i
          next if elb_timestamp_unixtime <= timestamp

          log.debug content.key
          object_keys << {
            key: content.key,
            prefix: matches[:prefix],
            account_id: matches[:account_id],
            region: matches[:region],
            logfile_date: matches[:logfile_date],
            logfile_elb_name: matches[:logfile_elb_name],
            elb_timestamp: matches[:elb_timestamp],
            elb_ip_address: matches[:elb_ip_address],
            logfile_hash: matches[:logfile_hash],
            elb_timestamp_unixtime: elb_timestamp_unixtime,
          }
        end
      end
      return object_keys
    rescue => e
      log.warn "error occurred: #{e.message}"
    end
  end

  def sort_object_key(src_object_keys)
    begin
      src_object_keys.sort do |a, b|
        a[:elb_timestamp_unixtime] <=> b[:elb_timestamp_unixtime]
      end
    rescue => e
      log.warn "error occurred: #{e.message}"
    end
  end

  def get_file_from_s3(object_name)
    begin
      log.debug "getting object from s3 name is #{object_name}"

      # read an object from S3 to a file and write buffer file
      File.open(@buf_file, File::WRONLY|File::CREAT|File::TRUNC) do |file|
        s3_client.get_object(
          bucket: @s3_bucketname,
          key: object_name
        ) do |chunk|
          file.write(chunk)
        end
      end
    rescue => e
      log.warn "error occurred: #{e.message}"
    end
  end

  def emit_lines_from_buffer_file(record_common)
    begin
      # emit per line
      File.open(@buf_file, File::RDONLY) do |file|
        file.each_line do |line|
          line_match = ACCESSLOG_REGEXP.match(line)
          unless line_match
            log.info "nomatch log found: #{line} in #{record_common['key']}"
            next
          end
  
          record = {
            "time" => line_match[:time].gsub(/Z/, "+0000"),
            "elb" => line_match[:elb],
            "client" => line_match[:client],
            "client_port" => line_match[:client_port],
            "backend" => line_match[:backend],
            "backend_port" => line_match[:backend_port],
            "request_processing_time" => line_match[:request_processing_time].to_f,
            "backend_processing_time" => line_match[:backend_processing_time].to_f,
            "response_processing_time" => line_match[:response_processing_time].to_f,
            "elb_status_code" => line_match[:elb_status_code],
            "backend_status_code" => line_match[:backend_status_code],
            "received_bytes" => line_match[:received_bytes].to_i,
            "sent_bytes" => line_match[:sent_bytes].to_i,
            "request_method" => line_match[:request_method],
            "request_uri" => line_match[:request_uri],
            "request_protocol" => line_match[:request_protocol],
            "user_agent" => line_match[:user_agent],
            "ssl_cipher" => line_match[:ssl_cipher],
            "ssl_protocol" => line_match[:ssl_protocol],
            "option3" => line_match[:option3],
          }

          router.emit(@tag, Fluent::Engine.now, record_common.merge(record))
        end
      end
    rescue => e
      log.warn "error occurred: #{e.message}"
    end
  end

  def run
    @loop.run
  end

  class TimerWatcher < Coolio::TimerWatcher
    def initialize(interval, repeat, &callback)
      @callback = callback
      on_timer # first call
      super(interval, repeat)
    end

    def on_timer
      @callback.call
    end
  end
end

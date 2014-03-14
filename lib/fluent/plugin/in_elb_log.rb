class Fluent::Elb_LogInput < Fluent::Input
  Fluent::Plugin.register_input('elb_log', self)
  
  LOGFILE_REGEXP = /^((?<prefix>.+?)\/|)AWSLogs\/(?<account_id>[0-9]{12})\/elasticloadbalancing\/(?<region>.+?)\/(?<logfile_date>[0-9]{4}\/[0-9]{2}\/[0-9]{2})\/[0-9]{12}_elasticloadbalancing_.+?_(?<logfile_elb_name>[^_]+)_(?<elb_timestamp>[0-9]{8}T[0-9]{4}Z)_(?<elb_ip_address>.+?)_(?<logfile_hash>.+)\.log$/
  ACCESSLOG_REGEXP = /^(?<time>.+?) (?<elb>.+?) (?<client>.+)\:(?<client_port>.+) (?<backend>.+)\:(?<backend_port>.+) (?<request_processing_time>.+?) (?<backend_processing_time>.+?) (?<response_processing_time>.+?) (?<elb_status_code>.+?) (?<backend_status_code>.+?) (?<received_bytes>.+?) (?<sent_bytes>.+?) \"(?<request_method>.+?) (?<request_uri>.+?) (?<request_protocol>.+?)\"$/

  config_param :access_key_id, :string, :default => nil
  config_param :secret_access_key, :string, :default => nil
  config_param :s3_bucketname, :string, :default => nil
  config_param :s3_prefix, :string, :default => nil
  config_param :s3_endpoint, :string, :default => 's3.amazon.com'
  config_param :timestamp_file, :string, :default => nil
  config_param :refresh_interval, :integer, :default => 300

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

    init_s3bucket

    @timestamp_file = File.open(@timestamp_file, File::RDWR|File::CREAT)
    @timestamp_file.sync = true

    @loop = Coolio::Loop.new
    timer_trigger = TimerWatcher.new(@refresh_interval, true, &method(:input))
    timer_trigger.attach(@loop)
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
      access_key_id: @access_key_id,
      secret_access_key: @secret_access_key
    ).buckets[@s3_bucketname]
  end

  def run
    @loop.run
  end

  def input
    $log.info "fluent-plugin-elb-log: input start"
   
    #get timestamp last proc
    @timestamp_file.rewind
    timestamp = @timestamp_file.read.to_i
    timestamp = 0 unless timestamp
    $log.info "fluent-plugin-elb-log: timestamp at start: " + Time.at(timestamp).to_s

    log_objects = []
    @bucket.objects.each do |obj|
      next if obj.last_modified.to_i <= timestamp
      matches = LOGFILE_REGEXP.match(obj.key)
      next unless matches
      next if !@s3_prefix.nil? && matches[:prefix] != @s3_prefix
      log_objects.push obj
    end

    # sort by timestamp
    log_objects.sort! do |a,b|
      LOGFILE_REGEXP.match(a.key)[:elb_timestamp] <=> LOGFILE_REGEXP.match(b.key)[:elb_timestamp]
    end

    log_objects.each do |obj|
      matches = LOGFILE_REGEXP.match(obj.key)
      timestamp = matches[:elb_timestamp].to_i
      record_common = {
        account_id: matches[:account_id],
        region: matches[:region],
        logfile_date: matches[:logfile_date],
        logfile_elb_name: matches[:logfile_elb_name],
        elb_ip_address: matches[:elb_ip_address],
        logfile_hash: matches[:logfile_hash],
      }

      obj.read do |line|
        line_match = ACCESSLOG_REGEXP.match(line)
        next unless line_match

        record = {
          time: line_match[:time].gsub(/Z/, "+0000"),
          elb: line_match[:elb],
          client: line_match[:client],
          client_port: line_match[:client_port],
          backend: line_match[:backend],
          backend_port: line_match[:backend_port],
          request_processing_time: line_match[:request_processing_time].to_f,
          backend_processing_time: line_match[:backend_processing_time].to_f,
          response_processing_time: line_match[:response_processing_time].to_f,
          elb_status_code: line_match[:elb_status_code],
          backend_status_code: line_match[:backend_status_code],
          received_bytes: line_match[:received_bytes],
          sent_bytes: line_match[:sent_bytes],
          request_method: line_match[:request_method],
          request_uri: line_match[:request_uri],
          request_protocol: line_match[:request_protocol],
        }
        
        Fluent::Engine.emit("elb.access", Fluent::Engine.now, record_common.merge(record))
      end
      # timestamp save
      @timestamp_file.rewind
      @timestamp_file.write(obj.last_modified.to_i)
      @timestamp_file.truncate(@timestamp_file.tell)
      $log.info "fluent-plugin-elb-log: timestamp save: " + obj.last_modified.to_s
    end
  end

  class TimerWatcher < Coolio::TimerWatcher
    def initialize(interval, repeat, &callback)
      @callback = callback
      super(interval, repeat)
    end

    def on_timer
      @callback.call
    end
  end
end

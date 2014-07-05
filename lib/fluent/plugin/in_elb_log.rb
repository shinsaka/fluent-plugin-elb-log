class Fluent::Elb_LogInput < Fluent::Input
  Fluent::Plugin.register_input('elb_log', self)

  LOGFILE_REGEXP = /^((?<prefix>.+?)\/|)AWSLogs\/(?<account_id>[0-9]{12})\/elasticloadbalancing\/(?<region>.+?)\/(?<logfile_date>[0-9]{4}\/[0-9]{2}\/[0-9]{2})\/[0-9]{12}_elasticloadbalancing_.+?_(?<logfile_elb_name>[^_]+)_(?<elb_timestamp>[0-9]{8}T[0-9]{4}Z)_(?<elb_ip_address>.+?)_(?<logfile_hash>.+)\.log$/
  ACCESSLOG_REGEXP = /^(?<time>\d{4}-\d{2}-\d{2}T\d{2}\:\d{2}\:\d{2}\.\d{6}Z) (?<elb>.+?) (?<client>.+)\:(?<client_port>.+) (?<backend>.+)\:(?<backend_port>.+) (?<request_processing_time>.+?) (?<backend_processing_time>.+?) (?<response_processing_time>.+?) (?<elb_status_code>.+?) (?<backend_status_code>.+?) (?<received_bytes>.+?) (?<sent_bytes>.+?) \"(?<request_method>.+?) (?<request_uri>.+?) (?<request_protocol>.+?)\"$/

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

    if @access_key_id.nil? and has_not_iam_role?
      raise Fluent::ConfigError.new("access_key_id is required")
    end
    if @secret_access_key.nil? and has_not_iam_role?
      raise Fluent::ConfigError.new("secret_access_key is required")
    end

    raise Fluent::ConfigError.new("s3_bucketname is required") unless @s3_bucketname
    raise Fluent::ConfigError.new("timestamp_file is required") unless @timestamp_file
    raise Fluent::ConfigError.new("s3 bucket fetch error #{@s3_bucketname}") if init_s3bucket.nil?
  end

  def start
    super

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
    options = {}
    if @access_key_id && @secret_access_key
      options[:access_key_id] = @access_key_id
      options[:secret_access_key] = @secret_access_key
    end
    options[:s3_endpoint] = @s3_endpoint if @s3_endpoint

    begin
      @bucket = AWS::S3.new(options).buckets[@s3_bucketname]
      @bucket.objects.count
    rescue => e
      $log.warn "fluent-plugin-elb-log: s3 bucket fetch error: #{e.message}"
      nil
    end
  end

  def run
    @loop.run
  end

  def input
    $log.info "fluent-plugin-elb-log: input start"

    # get timestamp last proc
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
        elb_timestamp: matches[:elb_timestamp],
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
          received_bytes: line_match[:received_bytes].to_i,
          sent_bytes: line_match[:sent_bytes].to_i,
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

  def has_iam_role?
    return @has_iam_role unless @has_iam_role.nil?

    require 'net/http'
    @has_iam_role  = false
    begin
      http = Net::HTTP.new('169.254.169.254', '80')
      http.open_timeout = 5 # sec
      response = http.request(Net::HTTP::Get.new('/latest/meta-data/iam/info'))
      @has_iam_role = true if response.code == '200'
    rescue => e
      $log.warn "fluent-plugin-elb-log: #{e.message}"
    end
    @has_iam_role
  end

  def has_not_iam_role?
    !has_iam_role?
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

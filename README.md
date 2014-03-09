# Amazon ELB log input plugin for fluentd

## Overview
- Amazon Web Services ELB log input plubin for fluentd

## Installation

    $ fluentd-gem fluent-plugin-elb-log

## AWS ELB Settings
- settings see: [Elastic Load Balancing](http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/enable-access-logs.html)
- developer guide: [](http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/access-log-collection.html)

## Configuration

```config
<source>
  type elb_log
  access_key_id     <access_key>
  secret_access_key <secret_access_key>
  s3_endpoint       <s3_endpoint>
  s3_bucketname     <bucketname>
  s3_prefix         <elb log's prefix>
  timestamp_file    <proc last file timestamp record filename>
  refresh_interval  <interval number by second>
</source>
```

### Example setting
```config
<source>
  type elb_log
  access_key_id     XXXXXXXXXXXXXXXXXXXX
  secret_access_key xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
  s3_endpoint       s3.amazonaws.com
  s3_bucketname     bucketname
  s3_prefix         prefix
  timestamp_file    elb_last_at.dat
  refresh_interval  300
</source>

<match **>
  type stdout
</match>
```

### json output example
```
{
    "account_id": "999999999999", 
    "backend": "192.168.30.127", 
    "backend_port": "80", 
    "backend_processing_time": "0.000985", 
    "backend_status_code": "200", 
    "client": "118.20.x.x", 
    "client_port": "46171", 
    "elb": "fluent-test-elb", 
    "elb_ip_address": "54.250.x.x", 
    "elb_status_code": "200", 
    "logfile_date": "2014/03/09", 
    "logfile_elb_name": "fluent-test-elb", 
    "logfile_hash": "xyz123ab", 
    "received_bytes": "0", 
    "region": "ap-northeast-1", 
    "request_method": "GET", 
    "request_processing_time": "0.000072", 
    "request_protocol": "HTTP/1.1", 
    "request_uri": "http://logfile_elb_name-00000000.ap-northeast-1.elb.amazonaws.com:80/", 
    "response_processing_time": "0.00007", 
    "sent_bytes": "9", 
    "time": "2014-03-09T04:10:33.785083Z"
}
```


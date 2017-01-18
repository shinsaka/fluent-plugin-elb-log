# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

Gem::Specification.new do |spec|
  spec.name          = "fluent-plugin-elb-log"
  spec.version       = "0.2.8"
  spec.authors       = ["shinsaka"]
  spec.email         = ["shinx1265@gmail.com"]
  spec.summary       = "Amazon ELB log input plugin"
  spec.description   = "Amazon ELB log input plugin for fluentd"
  spec.homepage      = "https://github.com/shinsaka/fluent-plugin-elb-log"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_dependency "fluentd", "~> 0"
  spec.add_dependency "aws-sdk", "~> 2"

  spec.add_development_dependency "bundler", "~> 1.7"
end

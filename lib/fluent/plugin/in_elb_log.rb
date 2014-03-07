class Fluent::Elb_LogInput < Fluent::Input
  Fluent::Plugin.register_input('elb_log', self)

  def configure(conf)
    super
  end

  def start
    super
  end

  def shutdown
    super
  end
end

require "akami/version"
require "akami/wsse"
require 'akami/wsse2'

module Akami

  # Returns a new <tt>Akami::WSSE</tt>.
  def self.wsse
    WSSE.new
  end

  def self.wsse2(params = {})
    Wsse2.new params
  end

end

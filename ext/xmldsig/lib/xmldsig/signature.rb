module OpenSSL::XML

class Signature

  attr_writer :pkey

  attr_reader :signature
  attr_reader :signature_algo, :c14n_algo 
  attr_reader :references
  attr_reader :certificates 
  attr_reader :key_infos

  def initialize(node)
    #TODO
  end

  def verify(doc)
    #TODO
  end

  def verify_digest(digest)
    #TODO
  end

end

class Reference

  attr_accessor :transforms
  attr_accessor :digest_algo, :digest_value

end

class Transform

  attr_accessor :algorithm

end

class XPath < Transform

  attr_accessor :namespaces, :expression

end

end



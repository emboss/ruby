module OpenSSL::XML

class Document
    
  attr_reader :encoding

  def initialize(bytes)
    @encoding = bytes
  end

  def sign(pkey, params=nil)
    signatures << create_signature(pkey, signer_cert, params)
  end

  def verify
    signatures.each { |sig|
      sig.verify(self)
    }
  end

  def signatures
    @signatures || @signatures = parse_signatures
  end

  private

  def parse_signatures
    [] #TODO
  end

  def create_signature(pkey, params=nil)
    #TODO
  end

end

end



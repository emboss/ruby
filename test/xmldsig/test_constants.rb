require_relative 'utils'

class TestConstants < XmlDsig::TestCase

  def test_signature_algorithms
    %w( RSA_SHA1 RSA_SHA256 RSA_SHA384 RSA_SHA512 
        DSA_SHA1 DSA_SHA256
        ECDSA_SHA1 ECDSA_SHA256 ECDSA_SHA384 ECDSA_SHA512 ).each{ |algo|
      assert_equal("UTF-8", XmlDsig::SignatureAlgorithms.const_get(algo.to_sym).encoding.name)
    }
  end

  def test_transform_algorithms
    %w( C14N_10 C14N_11 EXC_C14N_10
        C14N_10_COMMENTS C14N_11_COMMENTS EXC_C14N_10_COMMENTS
        BASE64
        ENVELOPED_SIGNATURE 
        XPATH XPATH_FILTER2 XSLT
      ).each{ |algo|
      assert_equal("UTF-8", XmlDsig::TransformAlgorithms.const_get(algo.to_sym).encoding.name)
    }
  end

  def test_digest_algorithms
    %w( SHA1 SHA256 SHA384 SHA512 ).each{ |algo|
      assert_equal("UTF-8", XmlDsig::DigestAlgorithms.const_get(algo.to_sym).encoding.name)
    }
  end

  def test_hmac_algorithms
    %w( HMAC_SHA1 HMAC_SHA256 HMAC_SHA384 HMAC_SHA512 ).each{ |algo|
      assert_equal("UTF-8", XmlDsig::HmacAlgorithms.const_get(algo.to_sym).encoding.name)
    }
  end

end


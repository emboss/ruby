require 'test/unit'
require 'xmldsig'
require_relative 'utils'

class Test_Sign < XmlDsig::TestCase

  def test_sign_default
    doc = sign_enveloped_default
    check_enveloped_default(doc)
    verify_all(doc, @cli_key.public_key)
  end

  def test_sign_default_read_bytes
    doc = XmlDsig::Document.new(sign_enveloped_default.bytes)
    check_enveloped_default(doc)
    verify_all(doc, @cli_key.public_key)
  end

  private

  def sign_enveloped_default
    doc = XmlDsig::Document.new(XmlDsig::TestUtils::TEST_DOC_UTF_8)
    assert_equal([], doc.signatures)
    doc.sign(@cli_key)
  end

  def verify_all(doc, pubkey)
    doc.verify
    doc.signatures[0].verify
    doc.signatures[0].verify(pub)
  end

  def check_enveloped_default(doc)
    assert_equal(1, doc.signatures.size)
    signature = doc.signatures[0]
    assert_equal(XmlDsig::SignatureMethod::RSA_SHA256, signature.signature_method)
    assert_equal(XmlDsig::Transforms::C14N_10, signature.canonicalization_method)
    assert_equal(1, signature.references.size)
    ref = signature.references[0]
    assert_equal("", ref.uri)
    assert_equal(1, ref.transforms.size)
    transform = ref.transforms[0]
    assert_equal(XmlDsig::Transforms::ENVELOPED_SIGNATURE, transform.algorithm)
  end

end


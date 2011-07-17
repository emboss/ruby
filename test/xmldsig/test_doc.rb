# encoding: UTF-8
require_relative 'utils'

class TestDocument < XmlDsig::TestCase

  def test_encoding_utf8_default
    raw = <<-_EOS_
<?xml version="1.0"?>
<root><element/></root>
_EOS_
    doc = XmlDsig::Document.new(raw)
    bytes = doc.bytes
    assert_equal(bytes.encoding, doc.encoding)
    assert_equal("UTF-8", bytes.encoding.name)
    assert_equal([], doc.signatures)
  end

  def test_encoding_utf8
    doc = XmlDsig::Document.new(XmlDsig::TestUtils::TEST_DOC_UTF_8)
    bytes = doc.bytes
    assert_equal(bytes.encoding, doc.encoding)
    assert_equal("UTF-8", bytes.encoding.name)
    assert_equal([], doc.signatures)
  end

  def test_encoding_iso_8859_1
    doc = XmlDsig::Document.new(XmlDsig::TestUtils::TEST_DOC_ISO_8859_1)
    bytes = doc.bytes
    assert_equal(bytes.encoding, doc.encoding)
    assert_equal("ISO-8859-1", bytes.encoding.name)
    assert_equal([], doc.signatures)
  end

  def test_encoding_us_ascii
    doc = XmlDsig::Document.new(XmlDsig::TestUtils::TEST_DOC_US_ASCII)
    bytes = doc.bytes
    assert_equal(bytes.encoding, doc.encoding)
    assert_equal("US-ASCII", bytes.encoding.name)
    assert_equal([], doc.signatures)
  end


end


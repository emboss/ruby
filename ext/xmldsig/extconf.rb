=begin
= $RCSfile$ -- Generator for Makefile

= Info
  XML Digital Signatures for Ruby
  Copyright (C) 2011  Martin Bosslet <Martin.Bosslet@googlemail.com>
  All rights reserved.

= Licence
  This program is licenced under the same licence as Ruby.
  (See the file 'LICENCE'.)

= Version
  $Id$
=end

require "mkmf"

dir_config("libxml")

message "=== Configuring XML Digital Signature support for Ruby ===\n"

if CONFIG['GCC'] == 'yes'
  $CPPFLAGS += " -Wall" unless $CPPFLAGS.split.include? "-Wall"
end

result = pkg_config("libxml-2.0") && have_header("libxml/xmlversion.h")

unless result
  message "=== Checking for libxml failed. ===\n"
  message "Makefile wasn't created. Fix the errors above.\n"
  exit 1
end

if checking_for('libxml version is 2.7.8 or later') {
    try_static_assert('LIBXML_VERSION >= 20708', 'libxml/xmlversion.h')
  }
end

message "=== Checking done. ===\n"

create_header
create_makefile("xmldsig")
message "Done.\n"

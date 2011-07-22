/*
 * $Id$
 * Xml Digital Signatures for Ruby
 * Copyright (C) 2011 Martin Bosslet <Martin.Bosslet@googlemail.com>
 * All rights reserved.
 */
/*
 * This program is licenced under the same licence as Ruby.
 * (See the file 'LICENCE'.)
 */
#include "xmldsig.h"
#include "xmldsig-internal.h"

VALUE cSignature;
VALUE cReference;
VALUE cTransform;

static VALUE
xmldsig_reference_init(int argc, VALUE *argv, VALUE self)
{
    VALUE transforms, opt_hash;
    rb_scan_args(argc, argv, "11", &transforms, &opt_hash);
    if (NIL_P(transforms)) 
	rb_raise(rb_eArgError, "Transforms may not be nil");
    rb_iv_set(self, "transforms", transforms);

    /* TODO: opt_hash */
    return self;
}

static VALUE
xmldsig_transform_init(VALUE self, VALUE algorithm)
{
    rb_iv_set(self, "algorithm", algorithm);
    return self;
}

void
Init_xmldsig_signature(void)
{
    cSignature = rb_define_class_under(mXMLDSIG, "Signature", rb_cObject);
    rb_attr(cSignature, sID, 1, 0, Qfalse);
    rb_attr(cSignature, rb_intern("signed_info_id"), 1, 0, Qfalse);
    rb_attr(cSignature, sC14N_METHOD, 1, 0, Qfalse);
    rb_attr(cSignature, sSIGNATURE_METHOD, 1, 0, Qfalse);
    rb_attr(cSignature, sREFERENCES, 1, 0, Qfalse);
    rb_attr(cSignature, rb_intern("signature_value"), 1, 0, Qfalse);
    rb_attr(cSignature, rb_intern("key_value"), 1, 0, Qfalse);
    
    cReference = rb_define_class_under(mXMLDSIG, "Reference", rb_cObject);
    rb_define_method(cReference, "initialize", xmldsig_reference_init, -1);
    rb_attr(cReference, sID, 1, 1, Qfalse);
    rb_attr(cReference, sURI, 1, 1, Qfalse);
    rb_attr(cReference, sTYPE, 1, 1, Qfalse);
    rb_attr(cReference, sTRANSFORMS, 1, 1, Qfalse);
    rb_attr(cReference, sDIGEST_METHOD, 1, 1, Qfalse);
    rb_attr(cReference, rb_intern("digest_value"), 1, 0, Qfalse);

    cTransform = rb_define_class_under(mXMLDSIG, "Transform", rb_cObject);
    rb_define_method(cTransform, "initialize", xmldsig_transform_init, 1);
    rb_attr(cTransform, rb_intern("algorithm"), 1, 1, Qfalse);
}

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

static xmlNodePtr int_xmldsig_prepare_signature(xmlDocPtr doc, sign_params_t *params, transform_t *transforms);
static void int_xmldsig_set_digest_values(transform_t *transforms);

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


static xmlNodePtr
int_xmldsig_prepare_signature(xmlDocPtr doc, sign_params_t *params, transform_t *transforms)
{
    /* TODO */
    return NULL;
}

static void
int_xmldsig_set_digest_values(transform_t *transforms)
{
    /* TODO */
}

VALUE
xmldsig_sig_sign(xmlDocPtr doc, sign_params_t *params)
{
    transform_t *transforms;
    transform_result_t *transform_result;
    xmlNodePtr signature_node;

    if (!(transforms = xmldsig_transforms_new()))
	rb_raise(rb_eRuntimeError, NULL);
    
    signature_node = int_xmldsig_prepare_signature(doc, params, transforms);
    transform_result = xmldsig_transforms_execute(transforms);
    int_xmldsig_set_digest_values(transforms);

    if (!transform_result->bytes) {
	/* need to apply a final default c14n 1.0 */
	transform_result->bytes_len = xmlC14NDocDumpMemory(doc, 
							   transform_result->nodes, 
							   0, 
							   NULL, 
							   0, 
							   &transform_result->bytes);
    }

    xmldsig_transforms_free(transforms);
    xmldsig_transform_result_free(transform_result);

    return Qnil;
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


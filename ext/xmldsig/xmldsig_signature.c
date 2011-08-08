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

VALUE
xmldsig_signature_init(xmlNodePtr signature)
{
    /* TODO */
    return Qnil;
}

static VALUE
xmldsig_reference_init(int argc, VALUE *argv, VALUE self)
{
    VALUE transforms, opt_hash;
    rb_scan_args(argc, argv, "11", &transforms, &opt_hash);
    if (NIL_P(transforms)) 
	rb_raise(rb_eArgError, "Transforms may not be nil");
    rb_ivar_set(self, sTRANSFORMS, transforms);

    /* TODO: opt_hash(id, type, uri) */

    return self;
}

static VALUE
xmldsig_transform_init(VALUE self, VALUE algorithm)
{
    rb_ivar_set(self, sALGORITHM, algorithm);
    return self;
}

static xmldsig_transform *
int_xmldsig_create_transform(xmldsig_sign_ctx *ctx, VALUE param_transform, xmlNodePtr transforms_node)
{
    xmlNodePtr transform_node;
    xmldsig_transform *transform;
    VALUE algorithm_id, algorithm;

    if (!(transform = xmldsig_transforms_new())) {
	xmldsig_sign_ctx_free(ctx);
	rb_raise(rb_eRuntimeError, NULL);
    }

    transform_node = xmlNewChild(transforms_node, ctx->ns_dsig, N_TRANSFORM, NULL);
    transform->node = transform_node;

    algorithm_id = rb_ivar_get(param_transform, sALGORITHM);
    transform->transformer = xmldsig_transformer_cb_for(algorithm_id);
    algorithm = rb_const_get(mTransformAlgorithms, SYM2ID(algorithm_id));
    StringValue(algorithm);
    rb_enc_associate(algorithm, ctx->doc_encoding);
    xmlNewProp(transform_node, A_ALGORITHM, CHAR2BYTES(RSTRING_PTR(algorithm)));

    /* TODO: XPath */

    return transform;
}

#define int_xmldsig_add_prop_to_ref(node, name, value, enc)	if (!NIL_P((value))) {							\
    								    StringValue((value));						\
    								    rb_enc_associate((value), (enc));					\
    								    xmlNewProp((node), (name), CHAR2BYTES(RSTRING_PTR((value)))); 	\
    								}

static xmldsig_reference *
int_xmldsig_create_reference(xmldsig_sign_ctx *ctx, VALUE param_ref)
{
    xmlNodePtr ref_node, transforms_node, digest_method_node;
    xmldsig_reference *ref;
    rb_encoding *encoding;
    VALUE id, uri, type, transforms, digest_method_id, digest_method;
    long transform_len, i;
    xmldsig_transform *cur_transform = NULL, *prev_transform = NULL;

    if (!(ref = xmldsig_reference_new())) {
	xmldsig_sign_ctx_free(ctx);
	rb_raise(rb_eRuntimeError, NULL);
    }

    encoding = ctx->doc_encoding;

    id = rb_ivar_get(param_ref, sID);
    uri = rb_ivar_get(param_ref, sURI);
    type = rb_ivar_get(param_ref, sTYPE);

    ref_node = xmlNewChild(ctx->signed_info, ctx->ns_dsig, N_REFERENCE, NULL);
    ref->node = ref_node;

    int_xmldsig_add_prop_to_ref(ref_node, A_ID, id, encoding);
    int_xmldsig_add_prop_to_ref(ref_node, A_TYPE, type, encoding);
    int_xmldsig_add_prop_to_ref(ref_node, A_URI, uri, encoding);

    transforms_node = xmlNewChild(ref_node, ctx->ns_dsig, N_TRANSFORMS, NULL);

    transforms = rb_ivar_get(param_ref, sTRANSFORMS);
    transform_len = RARRAY_LEN(transforms);

    for (i=0; i < transform_len; i++) {
	VALUE param_transform;

	param_transform = rb_ary_entry(transforms, i);
	cur_transform = int_xmldsig_create_transform(ctx, param_transform, transforms_node);

	if (!ref->transforms) {
	    ref->transforms = cur_transform;
	}

	cur_transform->prev = prev_transform;
	if (prev_transform)
	    prev_transform->next = cur_transform;
	prev_transform = cur_transform;
    }

    digest_method_node = xmlNewChild(ref_node, ctx->ns_dsig, N_DIGEST_METHOD, NULL);
    digest_method_id = rb_ivar_get(param_ref, sDIGEST_METHOD);
    digest_method = rb_const_get(mDigestAlgorithms, SYM2ID(digest_method_id));
    StringValue(digest_method);
    rb_enc_associate(digest_method, encoding);
    xmlNewProp(digest_method_node, A_ALGORITHM, CHAR2BYTES(RSTRING_PTR(digest_method)));

    xmlNewChild(ref_node, ctx->ns_dsig, N_DIGEST_VALUE, NULL);

    return ref;
}

static xmlNodePtr
int_xmldsig_prepare_signature(xmldsig_sign_ctx *ctx, xmldsig_sign_params *params)
{
    xmlNodePtr root, signature, signed_info, c14n_method_node, signature_method_node;
    VALUE refs, c14n_method, signature_method;
    long ref_len, i;
    xmldsig_reference *cur_ref = NULL, *prev_ref = NULL;

    root = xmlDocGetRootElement(ctx->doc);
    
    signature = xmlNewChild(root, ctx->ns_dsig, N_SIGNATURE, NULL);
    ctx->signature = signature;

    signed_info = xmlNewChild(signature, ctx->ns_dsig, N_SIGNED_INFO, NULL);
    ctx->signed_info = signed_info;

    c14n_method_node = xmlNewChild(signed_info, ctx->ns_dsig, N_C14N_METHOD, NULL);
    signature_method_node = xmlNewChild(signed_info, ctx->ns_dsig, N_SIGNATURE_METHOD, NULL);

    c14n_method = rb_const_get(mTransformAlgorithms, SYM2ID(params->c14n_method));
    StringValue(c14n_method);
    xmlNewProp(c14n_method_node, A_ALGORITHM, CHAR2BYTES(RSTRING_PTR(c14n_method)));

    signature_method = rb_const_get(mSignatureAlgorithms, SYM2ID(params->signature_method));
    StringValue(signature_method);
    xmlNewProp(signature_method_node, A_ALGORITHM, CHAR2BYTES(RSTRING_PTR(signature_method)));

    refs = params->references;
    ref_len = RARRAY_LEN(refs);

    for (i = 0; i < ref_len; i++) {
	VALUE param_ref;

	param_ref = rb_ary_entry(refs, i);
	cur_ref = int_xmldsig_create_reference(ctx, param_ref);

	if (!ctx->references) {
	    ctx->references = cur_ref;
	}

	cur_ref->prev = prev_ref;
	if (prev_ref)
	    prev_ref->next = cur_ref;
	prev_ref = cur_ref;
    }

    xmlNewChild(signature, ctx->ns_dsig, N_SIGNATURE_VALUE, NULL);
    return signature;
}

static void
int_xmldsig_set_reference_input_nodes(xmldsig_sign_ctx *ctx)
{
    xmldsig_reference *refs;

    refs = ctx->references;

    while (refs) {
	refs->transforms->in_nodes = xmldsig_input_nodes_for_ref(refs->node);
	refs = refs->next;
    }
}

static void	
int_xmldsig_compute_references(xmldsig_sign_ctx *ctx)
{
    xmldsig_reference *cur_ref;

    cur_ref = ctx->references;

    while (cur_ref) {
	int result;

	result = xmldsig_transforms_execute(cur_ref->transforms);
	if (result != 0) {
	    xmldsig_sign_ctx_free(ctx);
	    rb_raise(eXMLDSIGError, "Computing the references failed.");
	}
	cur_ref = cur_ref->next;
    }
}

static void
int_xmldsig_finalize_signature(xmldsig_sign_ctx *ctx)
{
    /* TODO */
}

static void
int_xmldsig_sign_ctx_init(xmldsig_sign_ctx *ctx, xmlDocPtr doc, rb_encoding *doc_encoding)
{
    ctx->doc = doc;
    ctx->doc_encoding = doc_encoding;
    ctx->ns_dsig = xmlNewNs(xmlDocGetRootElement(ctx->doc), NS_DSIG, NS_DSIG_PREFIX);
}

VALUE
xmldsig_sig_sign(xmlDocPtr doc, rb_encoding *doc_encoding, xmldsig_sign_params *params)
{
    xmldsig_sign_ctx *ctx;
    VALUE signature;

    if (!(ctx = xmldsig_sign_ctx_new()))
	rb_raise(rb_eRuntimeError, NULL);
    
    int_xmldsig_sign_ctx_init(ctx, doc, doc_encoding);
    int_xmldsig_prepare_signature(ctx, params);
    int_xmldsig_set_reference_input_nodes(ctx);
    int_xmldsig_compute_references(ctx);
    int_xmldsig_finalize_signature(ctx);

    xmldsig_sign_ctx_free(ctx);
    signature = xmldsig_signature_init(ctx->signature);
    return signature;
}

void
Init_xmldsig_signature(void)
{
    cSignature = rb_define_class_under(mXMLDSIG, "Signature", rb_cObject);
    rb_attr(cSignature, sID, 1, 0, Qfalse);
    rb_attr(cSignature, rb_intern("signed_info_id"), 1, 0, Qfalse);
    rb_attr(cSignature, sC14N_METHOD, 1, 0, Qfalse);
    rb_attr(cSignature, sSIGNATURE_METHOD, 1, 0, Qfalse);
    rb_attr(cSignature, sSIGNATURE_VALUE, 1, 0, Qfalse);
    rb_attr(cSignature, sREFERENCES, 1, 0, Qfalse);
    rb_attr(cSignature, sKEY_VALUE, 1, 0, Qfalse);
    
    cReference = rb_define_class_under(mXMLDSIG, "Reference", rb_cObject);
    rb_define_method(cReference, "initialize", xmldsig_reference_init, -1);
    rb_attr(cReference, sID, 1, 1, Qfalse);
    rb_attr(cReference, sURI, 1, 1, Qfalse);
    rb_attr(cReference, sTYPE, 1, 1, Qfalse);
    rb_attr(cReference, sTRANSFORMS, 1, 1, Qfalse);
    rb_attr(cReference, sDIGEST_METHOD, 1, 1, Qfalse);
    rb_attr(cReference, sDIGEST_VALUE, 1, 0, Qfalse);

    cTransform = rb_define_class_under(mXMLDSIG, "Transform", rb_cObject);
    rb_define_method(cTransform, "initialize", xmldsig_transform_init, 1);
    rb_attr(cTransform, sALGORITHM, 1, 1, Qfalse);
}


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

#define WrapXmlSig(klass, obj, s) do { \
    if (!(s)) { \
	rb_raise(rb_eRuntimeError, "xmlNodePtr was not initialized"); \
    } \
    (obj) = Data_Wrap_Struct((klass), 0, xmldsig_free_sig, (s)); \
} while (0)
#define GetXmlSig(obj, s) do { \
    Data_Get_Struct((obj), xmlNodePtr, (s)); \
    if (!(s)) { \
	rb_raise(rb_eRuntimeError, "xmlNodePtr could not be initialized"); \
    } \
} while (0)
#define SafeGetXmlSig(obj, s) do { \
    XMLDSIG_Check_Kind((s), cSignature); \
    GetXmlSig((obj), (s)); \
} while (0)

VALUE cSignature;
VALUE cReference;
VALUE cTransform;

static void
xmldsig_free_sig(xmlNodePtr sig)
{
    /* do nothing, node will be freed with the document */
}

static void
int_xmldsig_set_signature_method(VALUE signature, xmlNodePtr signature_node, rb_encoding *enc)
{
    xmlNodePtr signature_method;
    ID id;

    signature_method = xmldsig_find_child(signature_node, N_SIGNATURE_METHOD, NS_DSIG);
    id = xmldsig_signature_method_id_for(signature_method, enc);
    if (id == Qnil)
	rb_raise(eXMLDSIGError, "Unknown signature method");
    rb_ivar_set(signature, sivSIGNATURE_METHOD, ID2SYM(id));
} 

static void
int_xmldsig_set_c14n_method(VALUE signature, xmlNodePtr signature_node, rb_encoding *enc)
{
    xmlNodePtr c14n_method;
    ID id;

    c14n_method = xmldsig_find_child(signature_node, N_C14N_METHOD, NS_DSIG);
    id = xmldsig_transform_algorithm_id_for(c14n_method, enc);
    if (id == Qnil)
	rb_raise(eXMLDSIGError, "Unknown canonicalization method");
    rb_ivar_set(signature, sivC14N_METHOD, ID2SYM(id));
}

static void
int_xmldsig_set_signature_value(VALUE signature, xmlNodePtr signature_node)
{
    xmlNodePtr signature_value_node;
    unsigned char *tmp;
    VALUE signature_value;

    signature_value_node = xmldsig_find_child(signature_node, N_SIGNATURE_VALUE, NS_DSIG);
    tmp = xmlNodeGetContent(signature_value_node);
    signature_value = rb_str_new2((const char*)tmp);
    signature_value = rb_funcall(mBase64, rb_intern("decode64"), 1, signature_value);
    rb_ivar_set(signature, sivSIGNATURE_VALUE, signature_value);

    free(tmp);
}

static VALUE
xmldsig_signature_parse(xmlNodePtr signature, rb_encoding *enc)
{
    VALUE obj;
    
    if (!signature)
	rb_raise(rb_eArgError, "Signature is NULL");

    WrapXmlSig(cSignature, obj, signature);

    int_xmldsig_set_signature_method(obj, signature, enc);
    int_xmldsig_set_c14n_method(obj, signature, enc);
    int_xmldsig_set_signature_value(obj, signature);

    return obj;
}

static VALUE
xmldsig_reference_init(int argc, VALUE *argv, VALUE self)
{
    VALUE transforms, opt_hash;
    rb_scan_args(argc, argv, "11", &transforms, &opt_hash);
    if (NIL_P(transforms)) 
	rb_raise(rb_eArgError, "Transforms may not be nil");
    rb_ivar_set(self, sivTRANSFORMS, transforms);

    /* TODO: opt_hash(id, type, uri) */

    return self;
}

static VALUE
xmldsig_transform_init(VALUE self, VALUE algorithm)
{
    rb_ivar_set(self, sivALGORITHM, algorithm);
    return self;
}

static xmldsig_transform *
int_xmldsig_create_transform(xmldsig_sign_ctx *ctx, VALUE param_transform, xmlNodePtr transforms_node)
{
    xmlNodePtr transform_node;
    xmldsig_transform *transform;
    VALUE algorithm_id;

    if (!(transform = xmldsig_transforms_new())) {
	xmldsig_sign_ctx_free(ctx);
	rb_raise(rb_eRuntimeError, NULL);
    }

    transform_node = xmlNewChild(transforms_node, ctx->ns_dsig, N_TRANSFORM, NULL);
    transform->node = transform_node;

    algorithm_id = rb_ivar_get(param_transform, sivALGORITHM);
    transform->transformer = xmldsig_transformer_cb_for(algorithm_id);
    xmlNewProp(transform_node, A_ALGORITHM, xmldsig_transform_algorithm_str(SYM2ID(algorithm_id), ctx->doc_encoding));

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
    VALUE id, uri, type, transforms, digest_method_id;
    long transform_len, i;
    xmldsig_transform *cur_transform = NULL, *prev_transform = NULL;

    if (!(ref = xmldsig_reference_new())) {
	xmldsig_sign_ctx_free(ctx);
	rb_raise(rb_eRuntimeError, NULL);
    }

    encoding = ctx->doc_encoding;

    id = rb_ivar_get(param_ref, sivID);
    uri = rb_ivar_get(param_ref, sivURI);
    type = rb_ivar_get(param_ref, sivTYPE);

    ref_node = xmlNewChild(ctx->signed_info, ctx->ns_dsig, N_REFERENCE, NULL);
    ref->node = ref_node;

    int_xmldsig_add_prop_to_ref(ref_node, A_ID, id, encoding);
    int_xmldsig_add_prop_to_ref(ref_node, A_TYPE, type, encoding);
    int_xmldsig_add_prop_to_ref(ref_node, A_URI, uri, encoding);

    transforms_node = xmlNewChild(ref_node, ctx->ns_dsig, N_TRANSFORMS, NULL);

    transforms = rb_ivar_get(param_ref, sivTRANSFORMS);
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
    digest_method_id = rb_ivar_get(param_ref, sivDIGEST_METHOD);
    xmlNewProp(digest_method_node, A_ALGORITHM, xmldsig_digest_method_str(SYM2ID(digest_method_id), ctx->doc_encoding));

    xmlNewChild(ref_node, ctx->ns_dsig, N_DIGEST_VALUE, NULL);

    return ref;
}

static xmlNodePtr
int_xmldsig_prepare_signature(xmldsig_sign_ctx *ctx, xmldsig_sign_params *params)
{
    xmlNodePtr root, signature, signed_info, c14n_method_node, signature_method_node;
    VALUE refs;
    long ref_len, i;
    xmldsig_reference *cur_ref = NULL, *prev_ref = NULL;

    root = xmlDocGetRootElement(ctx->doc);
    
    signature = xmlNewChild(root, NULL, N_SIGNATURE, NULL);
    ctx->signature = signature;
    ctx->ns_dsig = xmlNewNs(ctx->signature, NS_DSIG, NS_DSIG_PREFIX);
    xmlSetNs(ctx->signature, ctx->ns_dsig); 
    
    signed_info = xmlNewChild(signature, ctx->ns_dsig, N_SIGNED_INFO, NULL);
    ctx->signed_info = signed_info;

    c14n_method_node = xmlNewChild(signed_info, ctx->ns_dsig, N_C14N_METHOD, NULL);
    signature_method_node = xmlNewChild(signed_info, ctx->ns_dsig, N_SIGNATURE_METHOD, NULL);

    xmlNewProp(c14n_method_node, A_ALGORITHM, xmldsig_transform_algorithm_str(SYM2ID(params->c14n_method), ctx->doc_encoding));
    xmlNewProp(signature_method_node, A_ALGORITHM, xmldsig_signature_method_str(SYM2ID(params->signature_method), ctx->doc_encoding));

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

static VALUE
int_xmldsig_transform_result_bytes(xmldsig_reference *ref)
{
    xmldsig_transform *cur;

    cur = ref->transforms;
    
    while (cur->next)
	cur = cur->next;

    return rb_str_new((const char *)cur->out_buf, cur->out_len);
}

static void
int_xmldsig_finalize_references(xmldsig_sign_ctx *ctx)
{
    xmldsig_reference *cur_ref;
    xmlNodePtr digest_method_node;
    VALUE transform_result_bytes, digest, digest_value;
    xmlNodePtr digest_value_node;

    cur_ref = ctx->references;

    while (cur_ref) {
	transform_result_bytes = int_xmldsig_transform_result_bytes(cur_ref);
	digest_method_node = xmldsig_find_child(cur_ref->node, N_DIGEST_METHOD, NS_DSIG);
	digest = xmldsig_digest_for(digest_method_node, ctx->doc_encoding);
	if (NIL_P(digest)) {
	    xmldsig_sign_ctx_free(ctx);
	    rb_raise(eXMLDSIGError, "Unknown digest: %s", xmlGetProp(digest_method_node, A_ALGORITHM));
	}
	digest_value = rb_funcall(digest, rb_intern("digest"), 1, transform_result_bytes);
	digest_value = rb_funcall(mBase64, rb_intern("encode64"), 1, digest_value);
	digest_value_node = xmldsig_find_child(cur_ref->node, N_DIGEST_VALUE, NS_DSIG);
	xmlNodeAddContent(digest_value_node, CHAR2BYTES(StringValueCStr(digest_value)));

	cur_ref = cur_ref->next;
    }
}

static void
int_xmldsig_finalize_signature(xmldsig_sign_ctx *ctx, VALUE key)
{
    unsigned char *canonical_bytes;
    int len_bytes;
    xmlNodePtr signed_info_node, signature_method_node, signature_value_node;
    VALUE digest, sig_value;

    signed_info_node = xmldsig_find_child(ctx->signature, N_SIGNED_INFO, NS_DSIG);
    len_bytes = xmldsig_canonicalize_signed_info(signed_info_node, ctx->doc_encoding, &canonical_bytes);

    if (len_bytes < 0) {
	xmldsig_sign_ctx_free(ctx);
	rb_raise(eXMLDSIGError, "Error when canonicalizing the SignedInfo");
    }
    signature_method_node = xmldsig_find_child(signed_info_node, N_SIGNATURE_METHOD, NS_DSIG);
    digest = xmldsig_digest_for_signature_method(signature_method_node, ctx->doc_encoding);
    if (!digest) {
	xmldsig_sign_ctx_free(ctx);
	rb_raise(eXMLDSIGError, "Unknown signature method: %s", xmlGetProp(signature_method_node, A_ALGORITHM));
    }

    sig_value = rb_funcall(key, rb_intern("sign"), 2, digest, rb_str_new((const char*)canonical_bytes, len_bytes));
    sig_value = rb_funcall(mBase64, rb_intern("encode64"), 1, sig_value);
    signature_value_node = xmldsig_find_child(ctx->signature, N_SIGNATURE_VALUE, NS_DSIG);
    xmlNodeAddContent(signature_value_node, CHAR2BYTES(StringValueCStr(sig_value)));
}

static void
int_xmldsig_sign_ctx_init(xmldsig_sign_ctx *ctx, xmlDocPtr doc, rb_encoding *doc_encoding)
{
    ctx->doc = doc;
    ctx->doc_encoding = doc_encoding;
}

VALUE
xmldsig_sig_sign(xmlDocPtr doc, rb_encoding *doc_encoding, xmldsig_sign_params *params)
{
    xmldsig_sign_ctx *ctx;

    if (!(ctx = xmldsig_sign_ctx_new()))
	rb_raise(rb_eRuntimeError, NULL);
    
    int_xmldsig_sign_ctx_init(ctx, doc, doc_encoding);
    int_xmldsig_prepare_signature(ctx, params);
    int_xmldsig_set_reference_input_nodes(ctx);
    int_xmldsig_compute_references(ctx);
    int_xmldsig_finalize_references(ctx);
    int_xmldsig_finalize_signature(ctx, params->key);

    xmldsig_sign_ctx_free(ctx);
    return xmldsig_signature_parse(ctx->signature, doc_encoding);
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


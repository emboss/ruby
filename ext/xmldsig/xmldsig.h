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

#if !defined(_XMLDSIG_H_)
#define _XMLDSIG_H_

#include RUBY_EXTCONF_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <ruby.h>
#include <ruby/io.h>

#ifdef HAVE_ASSERT_H
#  include <assert.h>
#else
#  define assert(condition)
#endif

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/c14n.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

/*
 * Common Module
 */
extern VALUE mXMLDSIG;

/*
 * Common Error Class
 */
extern VALUE eXMLDSIGError;

/*
 * Algorithm constants
 */
extern VALUE mSignatureAlgorithms;
extern VALUE mTransformAlgorithms;
extern VALUE mDigestAlgorithms;
extern VALUE mHmacAlgorithms;

extern ID sRSA_SHA1, sRSA_SHA256, sRSA_SHA384, sRSA_SHA512;
extern ID sDSA_SHA1, sDSA_SHA256;
extern ID sECDSA_SHA1, sECDSA_SHA256, sECDSA_SHA384, sECDSA_SHA512;

extern ID sC14N_10, sC14N_11, sEXC_C14N_10, sC14N_10_COMMENTS, sC14N_11_COMMENTS, sEXC_C14N_10_COMMENTS;
extern ID sBASE64;
extern ID sENVELOPED_SIGNATURE;
extern ID sXPATH, sXPATH_FILTER2, sXSLT;

extern ID sSHA1, sSHA256, sSHA384, sSHA512;

extern ID sHMAC_SHA1, sHMAC_SHA256, sHMAC_SHA384, sHMAC_SHA512;

/*
 * CheckTypes
 */
#define XMLDSIG_Check_Kind(obj, klass) do {\
  if (!rb_obj_is_kind_of((obj), (klass))) {\
    rb_raise(rb_eTypeError, "wrong argument (%s)! (Expected kind of %s)",\
               rb_obj_classname(obj), rb_class2name(klass));\
  }\
} while (0)

#define XMLDSIG_Check_Instance(obj, klass) do {\
  if (!rb_obj_is_instance_of((obj), (klass))) {\
    rb_raise(rb_eTypeError, "wrong argument (%s)! (Expected instance of %s)",\
               rb_obj_classname(obj), rb_class2name(klass));\
  }\
} while (0)

#define XMLDSIG_Check_Same_Class(obj1, obj2) do {\
  if (!rb_obj_is_instance_of((obj1), rb_obj_class(obj2))) {\
    rb_raise(rb_eTypeError, "wrong argument type");\
  }\
} while (0)

/*
 * Include all parts
 */
#include "xmldsig_document.h"
#include "xmldsig_signature.h"

VALUE xml_dsig_get_encoding(xmlDocPtr doc);

void Init_xmldsig(void);

#if defined(__cplusplus)
}
#endif

#endif /* _XMLDSIG_H_ */

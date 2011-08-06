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


int
xmldsig_enveloped_signature_transform(xmldsig_transform *transform)
{
    /* TODO */
    return 1;
}

xmldsig_transformer_cb xmldsig_transformer_cb_for(VALUE algorithm)
{
   ID algo_id;

   algo_id = SYM2ID(algorithm);
   if (algo_id == sENVELOPED_SIGNATURE)
       return xmldsig_enveloped_signature_transform;
   else {
       rb_raise(rb_eRuntimeError, "Unsupported transform algorithm");
       return NULL; /* dummy */
   }
}

xmldsig_transform_result *
xmldsig_transforms_execute(xmldsig_transform *transforms)
{
    /* TODO */
    return NULL;
}

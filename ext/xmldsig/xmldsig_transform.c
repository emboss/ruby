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
    xmlNodePtr signature;
    xmlNodeSetPtr signature_nodes;
    int retval;

    signature = xmldsig_find_parent(transform->node, N_SIGNATURE, NS_DSIG);
    if (!signature)
	return 1;
    
    signature_nodes = xmldsig_node_set_create(signature->doc, signature, 1);
    transform->out_nodes = xmldsig_node_set_subtract(transform->in_nodes, signature_nodes);

    if (!transform->out_nodes)
	retval = 1;
    else
	retval = 0;

    xmlXPathFreeNodeSet(signature_nodes);
    return retval;
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

int
xmldsig_transforms_execute(xmldsig_transform *transforms)
{
    xmldsig_transform *cur;

    cur = transforms;

    while (cur) {
	int res;

	res = cur->transformer(cur);
	if (res != 0)
	    return res;

	if (cur->next) {
	    xmldsig_transform *next;

	    next = cur->next;
	    next->in_nodes = cur->out_nodes;
	    next->in_len = cur->out_len;
	    next->in_buf = cur->out_buf;
	}
	else {
	    if (!cur->out_buf) {
		/* need to apply a final default c14n 1.0 */
		cur->out_len = xmlC14NDocDumpMemory(cur->node->doc, 
					     cur->out_nodes, 
					     XML_C14N_1_0, 
					     NULL, 
					     0, 
					     &(cur->out_buf));
	    }
	}
	cur = cur->next;
    }

    return 0;
}

xmlNodeSetPtr
xmldsig_input_nodes_for_ref(xmlNodePtr ref_node)
{
    unsigned char *uri;
    xmlNodeSetPtr retval;

    uri = xmlGetProp(ref_node, A_URI);

    if (strcmp((const char *)uri, "") == 0) {
	retval = xmldsig_node_set_create(ref_node->doc, NULL, 1);
    }
    else {
	free(uri);
	rb_raise(rb_eRuntimeError, "Currently only \"\" URI values are supported.");
	return NULL;
    }

    free(uri);
    return retval;
}

int
xmldsig_canonicalize_signed_info(xmlNodePtr signed_info, rb_encoding *doc_encoding, unsigned char **out_buf)
{
    xmlNodePtr c14n_method_node;
    xmlNodeSetPtr nodes;
    int mode, with_comments, len;

    c14n_method_node = xmldsig_find_child(signed_info, N_C14N_METHOD, NS_DSIG);
    if (!xmldsig_c14n_method_for(c14n_method_node, doc_encoding, &mode, &with_comments))
	return 0;

    nodes = xmldsig_node_set_create(signed_info->doc, signed_info, with_comments);
    xmldsig_add_parent_namespaces(signed_info, nodes);

    len = xmlC14NDocDumpMemory(signed_info->doc,
	    			nodes,
				mode,
				NULL,
				with_comments,
				out_buf);
    xmlXPathFreeNodeSet(nodes);
    return len;
}


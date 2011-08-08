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

#define XMLDSIG_INTERSECT 0
#define XMLDSIG_SUBTRACT 1

const unsigned char*
xmldsig_ns_href_get(const xmlNodePtr node)
{
    xmlNsPtr ns;

    if (node->ns != NULL)
	return node->ns->href;

    ns = xmlSearchNs(node->doc, node, NULL);

    if (ns != NULL) 
	return ns->href;
    
    return NULL;
}

xmlNodePtr
xmldsig_find_parent(xmlNodePtr node, const unsigned char *name, const unsigned char *ns)
{
    if (xmldsig_node_name_cmp(node, name, ns))
	return node;
    else if (node->parent != NULL)
	return xmldsig_find_parent(node->parent, name, ns);
    return NULL;
}

xmlNodePtr
xmldsig_find_child(xmlNodePtr node, const unsigned char *name, const unsigned char *ns)
{
    xmlNodePtr cur, ret;

    cur = node;
    while (cur != NULL) {
	if ((cur->type == XML_ELEMENT_NODE) && xmldsig_node_name_cmp(cur, name, ns)) {
	    return cur;
	}
	if (cur->children != NULL) {
	    ret = xmldsig_find_child(cur->children, name, ns);
	    if (ret != NULL) {
		return ret;
	    }
	}
	cur = cur->next;
    }
    return NULL;
}

/* Document order is element, namespaces, attributes, then children */
static void
int_xmldsig_nodeset_tree_recursive(xmlNodePtr cur, xmlNodePtr parent, xmlNodeSetPtr set, int with_comments)
{
    if (with_comments || (cur->type != XML_COMMENT_NODE)) {
	if (cur->type == XML_NAMESPACE_DECL) {
	    xmlXPathNodeSetAddNs(set, parent, (xmlNsPtr)cur);
	}
	else { 
    	    xmlXPathNodeSetAdd(set, cur);
	}
    }

    if (cur->type == XML_ELEMENT_NODE) {
	xmlAttrPtr attr;
	xmlNsPtr ns;

	ns = cur->nsDef;
	while (ns) {
	    int_xmldsig_nodeset_tree_recursive((xmlNodePtr)ns, cur, set, with_comments);
	    ns = ns->next;
	}

	attr = (xmlAttrPtr)cur->properties;
	while (attr) {
	    int_xmldsig_nodeset_tree_recursive((xmlNodePtr)attr, cur, set, with_comments);
	    attr = attr->next;
	}
    }

    if ((cur->type == XML_ELEMENT_NODE) || (cur->type == XML_DOCUMENT_NODE)) {
	xmlNodePtr node;

	node = cur->children;
	while (node) {
	    int_xmldsig_nodeset_tree_recursive(node, cur, set, with_comments);
	    node = node->next;
	}
    }
}

xmlNodeSetPtr
xmldsig_node_set_create(xmlDocPtr doc, xmlNodePtr parent, int with_comments)
{
    xmlNodeSetPtr set;
    xmlNodePtr start;

    if (parent == NULL)
	start = (xmlNodePtr)doc;
    else
	start = parent;

    set = xmlXPathNodeSetCreate(NULL);
    int_xmldsig_nodeset_tree_recursive(start, NULL, set, with_comments);

    return set;
}

static xmlNodeSetPtr
int_xmldsig_node_set_combine(xmlNodeSetPtr set1, xmlNodeSetPtr set2, int op)
{
    switch (op) {
	case XMLDSIG_INTERSECT:
	    return xmlXPathIntersection(set1, set2);
	    break;
	case XMLDSIG_SUBTRACT:
	    return xmlXPathDifference(set1, set2);
	    break;
    }

    rb_raise(rb_eRuntimeError, "Unknown op");
    return NULL;
}

xmlNodeSetPtr
xmldsig_node_set_intersect(xmlNodeSetPtr set1, xmlNodeSetPtr set2)
{
    return int_xmldsig_node_set_combine(set1, set2, XMLDSIG_INTERSECT);
}

xmlNodeSetPtr
xmldsig_node_set_subtract(xmlNodeSetPtr set1, xmlNodeSetPtr set2)
{
    return int_xmldsig_node_set_combine(set1, set2, XMLDSIG_SUBTRACT);
}


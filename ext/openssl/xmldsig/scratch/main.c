#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

int  execute_xpath_expression(void);
void create_signature(void);
int  register_namespaces(xmlXPathContextPtr xpathCtx, const xmlChar* nsList);
void print_xpath_nodes(xmlNodeSetPtr nodes, FILE* output);

int
main(int argc, char **argv) {
    /* Init libxml */
    xmlInitParser();
    LIBXML_TEST_VERSION

    execute_xpath_expression();
    create_signature();

    /* Shutdown libxml */
    xmlCleanupParser();

    /*
     * this is to debug memory for regression tests
     */
    xmlMemoryDump();
    return 0;
}

void create_signature(void)
{
    xmlDocPtr doc;
    xmlNodePtr root, signature, signed_info;
    xmlNsPtr ns_dsig;
    FILE *out;

    const unsigned char *s_dsig_ns = "http://www.w3.org/2000/09/xmldsig#";

    doc = xmlParseFile("example.xhtml");
    if (doc == NULL) {
	fprintf(stderr, "Error: unable to parse file example.xhtml\n");
	return;
    }

    root = xmlDocGetRootElement(doc);
    ns_dsig = xmlNewNs(root, s_dsig_ns, "dsig");
    signature = xmlNewChild(root, ns_dsig, "Signature", NULL);
    signed_info = xmlNewChild(signature, ns_dsig, "SignedInfo", NULL);

    if (!(out = fopen("out.xml", "wb"))) {
        fprintf(stderr, "Error: unable to open out.xml for output\n");
	return;
    }

    if (xmlDocDump(out, doc) < 0) {
        fprintf(stderr, "Error: Could not write document\n");
	return;
    }

    fclose(out);
}

int
execute_xpath_expression(void) {
    xmlDocPtr doc;
    xmlXPathContextPtr xpathCtx;
    xmlXPathObjectPtr xpathObj;
    const xmlChar *xpathExpr = "//xhtml:div";
    
    /* Load XML document */
    doc = xmlParseFile("example.xhtml");
    if (doc == NULL) {
	fprintf(stderr, "Error: unable to parse file example.xhtml\n");
	return(-1);
    }

    /* Create xpath evaluation context */
    xpathCtx = xmlXPathNewContext(doc);
    if(xpathCtx == NULL) {
        fprintf(stderr,"Error: unable to create new XPath context\n");
        xmlFreeDoc(doc);
        return(-1);
    }

    if (xmlXPathRegisterNs (xpathCtx, (xmlChar*)"xhtml", (xmlChar*)"http://www.w3.org/1999/xhtml") < 0) {
        fprintf(stderr,"Error: failed to register namespace\n");
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        return(-1);
    }

    /* Evaluate xpath expression */
    xpathObj = xmlXPathEvalExpression(xpathExpr, xpathCtx);
    if(xpathObj == NULL) {
        fprintf(stderr,"Error: unable to evaluate xpath expression \"%s\"\n", xpathExpr);
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        return(-1);
    }

    /* Print results */
    print_xpath_nodes(xpathObj->nodesetval, stdout);

    /* Cleanup */
    xmlXPathFreeObject(xpathObj);
    xmlXPathFreeContext(xpathCtx);
    xmlFreeDoc(doc);

    return(0);
}

/**
 * print_xpath_nodes:
 * @nodes:		the nodes set.
 * @output:		the output file handle.
 *
 * Prints the @nodes content to @output.
 */
void
print_xpath_nodes(xmlNodeSetPtr nodes, FILE* output) {
    xmlNodePtr cur;
    int size;
    int i;

    assert(output);
    size = (nodes) ? nodes->nodeNr : 0;

    fprintf(output, "Result (%d nodes):\n", size);
    for(i = 0; i < size; ++i) {
	assert(nodes->nodeTab[i]);

	if(nodes->nodeTab[i]->type == XML_NAMESPACE_DECL) {
	    xmlNsPtr ns;

	    ns = (xmlNsPtr)nodes->nodeTab[i];
	    cur = (xmlNodePtr)ns->next;
	    if(cur->ns) {
	        fprintf(output, "= namespace \"%s\"=\"%s\" for node %s:%s\n",
		    ns->prefix, ns->href, cur->ns->href, cur->name);
	    } else {
	        fprintf(output, "= namespace \"%s\"=\"%s\" for node %s\n",
		    ns->prefix, ns->href, cur->name);
	    }
	} else if(nodes->nodeTab[i]->type == XML_ELEMENT_NODE) {
	    cur = nodes->nodeTab[i];
	    if(cur->ns) {
    	        fprintf(output, "= element node \"%s:%s\"\n",
		    cur->ns->href, cur->name);
	    } else {
    	        fprintf(output, "= element node \"%s\"\n",
		    cur->name);
	    }
	} else {
	    cur = nodes->nodeTab[i];
	    fprintf(output, "= node \"%s\": type %d\n", cur->name, cur->type);
	}
    }
}

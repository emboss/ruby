#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/c14n.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/buffer.h>

int  execute_xpath_expression(void);
void create_signature(void);
void create_signature_nodes(xmlDocPtr doc, xmlChar *digested_doc);
xmlNodePtr create_signed_info(xmlNodePtr signature, xmlNsPtr ns_dsig, xmlChar *digested_doc);
xmlChar *digest_document(xmlDocPtr doc);
xmlChar *base64(const xmlChar *input, int length);
int digest(xmlChar *input, int len, xmlChar **out);
int  register_namespaces(xmlXPathContextPtr xpathCtx, const xmlChar* nsList);
void print_xpath_nodes(xmlNodeSetPtr nodes, FILE* output);

int
main(int argc, char **argv) {
    /* Init libxml */
    xmlInitParser();
    LIBXML_TEST_VERSION

    /* execute_xpath_expression(); */
    create_signature();

    /* Shutdown libxml */
    xmlCleanupParser();

    return 0;
}

void create_signature(void)
{
    xmlDocPtr doc;
    xmlChar *digested_doc;
    FILE *out;
    
    doc = xmlParseFile("example.xhtml");
    if (doc == NULL) {
	fprintf(stderr, "Error: unable to parse file example.xhtml\n");
	return;
    }

    digested_doc = digest_document(doc);
    create_signature_nodes(doc, digested_doc);
    
    if (!(out = fopen("out.xml", "wb"))) {
        fprintf(stderr, "Error: unable to open out.xml for output\n");
	return;
    }

    if (xmlDocDump(out, doc) < 0) {
        fprintf(stderr, "Error: Could not write document\n");
	return;
    }

    xmlFree(digested_doc);
    xmlFreeDoc(doc);
    fclose(out);
}

void
create_signature_nodes(xmlDocPtr doc, xmlChar *digested_doc) {
    xmlNodePtr root, signature, signed_info;
    xmlNsPtr ns_dsig;
    xmlNodeSetPtr ns;
    xmlChar *canon, *digest_val, *b64;
    int len;
    const xmlChar *s_dsig_ns = BAD_CAST "http://www.w3.org/2000/09/xmldsig#";
    
    root = xmlDocGetRootElement(doc);
    ns_dsig = xmlNewNs(root, s_dsig_ns, BAD_CAST "dsig");
    signature = xmlNewChild(root, ns_dsig, BAD_CAST "Signature", NULL);
    signed_info = create_signed_info(signature, ns_dsig, digested_doc);
    ns = xmlXPathNodeSetCreate(signed_info);
    len = xmlC14NDocDumpMemory(doc, ns, 0, NULL, 0, &canon);
    len = digest(canon, len, &digest_val);
    /* TODO: Sign the digest */
    b64 = base64(digest_val, len);
    xmlFree(canon);
    xmlFree(digest_val);
    xmlNewChild(signature, ns_dsig, BAD_CAST "SignatureValue", b64);
}

xmlNodePtr
create_signed_info(xmlNodePtr signature, xmlNsPtr ns_dsig, xmlChar *digested_doc) {
    xmlNodePtr signed_info, can_method, 
               sig_method, reference, transforms, transform,
               dig_method;
    signed_info = xmlNewChild(signature, ns_dsig, BAD_CAST "SignedInfo", NULL);
    can_method = xmlNewChild(signed_info, ns_dsig, BAD_CAST "CanonicalizationMethod", NULL);
    xmlNewProp(can_method, BAD_CAST "Algorithm", BAD_CAST "http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
    sig_method = xmlNewChild(signed_info, ns_dsig, BAD_CAST "SignatureMethod", NULL);
    xmlNewProp(sig_method, BAD_CAST "Algorithm", BAD_CAST "http://www.w3.org/2000/09/xmldsig#rsa-sha1");
    reference = xmlNewChild(signed_info, ns_dsig, BAD_CAST "Reference", NULL);
    xmlNewProp(reference, BAD_CAST "URI", BAD_CAST "");
    transforms = xmlNewChild(reference, ns_dsig, BAD_CAST "Transforms", NULL);
    transform = xmlNewChild(transforms, ns_dsig, BAD_CAST "Transform", NULL);
    xmlNewProp(transform, BAD_CAST "Algorithm", BAD_CAST "http://www.w3.org/2000/09/xmldsig#enveloped-signature");
    dig_method = xmlNewChild(reference, ns_dsig, BAD_CAST "DigestMethod", NULL);
    xmlNewProp(dig_method, BAD_CAST "Algorithm", BAD_CAST "http://www.w3.org/2000/09/xmldsig#sha1");
    xmlNewChild(reference, ns_dsig, BAD_CAST "DigestValue", digested_doc);
    return signed_info;
}

xmlChar *
digest_document(xmlDocPtr doc) {
    xmlXPathContextPtr xpathCtx;
    xmlXPathObjectPtr xpathObj;
    xmlChar *canon, *digest_val, *b64;
    int len;
    const xmlChar *xpathExpr = BAD_CAST "(//. | //@* | //namespace::*)";
    
    if (!(xpathCtx = xmlXPathNewContext(doc))) {
        fprintf(stderr,"Error: unable to create new XPath context\n");
        xmlFreeDoc(doc);
    }
    
    if (!(xpathObj = xmlXPathEvalExpression(xpathExpr, xpathCtx))) {
        fprintf(stderr,"Error: unable to evaluate xpath expression \"%s\"\n", xpathExpr);
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
    }

    len = xmlC14NDocDumpMemory(doc, xpathObj->nodesetval, 0, NULL, 0, &canon);
    len = digest(canon, len, &digest_val);
    b64 = base64(digest_val, len);
    xmlFree(canon);
    xmlFree(digest_val);
    return b64;
}

int 
digest(xmlChar *input, int len, xmlChar **out) {
    EVP_MD_CTX *ctx;
    xmlChar md[SHA_DIGEST_LENGTH];
 
    if (!(ctx = EVP_MD_CTX_create())) {
        return(-1);
    }
    
    EVP_DigestInit(ctx, EVP_sha1());
    EVP_DigestUpdate(ctx, input, len);
    EVP_DigestFinal(ctx, md, NULL);
    
    *out = base64(md, SHA_DIGEST_LENGTH);
    return SHA_DIGEST_LENGTH;
}

xmlChar *base64(const xmlChar *input, int length)
{
  BIO *bmem, *b64;
  BUF_MEM *bptr;

  b64 = BIO_new(BIO_f_base64());
  bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);
  BIO_write(b64, input, length);
  BIO_flush(b64);
  BIO_get_mem_ptr(b64, &bptr);

  xmlChar *buff = (xmlChar *)malloc(bptr->length);
  memcpy(buff, bptr->data, bptr->length-1);
  buff[bptr->length-1] = 0;

  BIO_free_all(b64);

  return buff;
}

int
execute_xpath_expression(void) {
    xmlDocPtr doc;
    xmlXPathContextPtr xpathCtx;
    xmlXPathObjectPtr xpathObj;
    const xmlChar *xpathExpr = BAD_CAST "//xhtml:div";
    
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

    if (xmlXPathRegisterNs (xpathCtx, BAD_CAST "xhtml", BAD_CAST "http://www.w3.org/1999/xhtml") < 0) {
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

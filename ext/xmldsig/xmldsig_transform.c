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

transform_t *
xmldsig_transforms_new(void)
{
    return NULL;
}

void
xmldsig_transforms_free(transform_t *transform)
{
}

transform_result_t *
xmldsig_transforms_execute(transform_t *transforms)
{
    return NULL;
}

transform_result_t *
xmldsig_transform_result_new()
{
    return null;
}

void
xmldsig_transform_result_free(transform_result_t *result)
{
}

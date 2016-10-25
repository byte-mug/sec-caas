/*
 * Copyright (c) 2016 Simon Schmidt
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include <secrbac/secrbac_res.h>
#include <secrbac/aclfmt.h>

static const char* const subject_attrs[] = {
	SECRBAC_ROLES,
};

static const char* const resource_attrs[] = {
	SECRBAC_ACL,
};

enum {
	SMOP_APPEND = SECMAC_OP_APPEND,
	SMOP_WRITE  = SECMAC_OP_WRITE,
	SMOP_READ   = SECMAC_OP_READ|SECMAP_OP_CONNECT,
	SMOP_EXEC   = SECMAC_OP_EXEC|SECMAP_OP_ACCEPT,
	SMOP_ADMIN  = SECMAP_OP_CH_MODE|SECMAP_OP_CH_OWNER|SECMAP_OP_CH_ATTRIB|SECMAP_OP_WRITEMETA,
	SMOP_LINK   = SECMAP_OP_LINK,
	SMOP_DELETE = SECMAC_OP_DELETE,
	SMOP_RENAME = SECMAP_OP_RENAME,
};

enum {
	SMOP_UNSUP = ~ (SMOP_APPEND|SMOP_WRITE|SMOP_READ|SMOP_EXEC|SMOP_ADMIN),
};

enum {
	ACL_NO_APPEND = SECRBAC_MASK_NO_APPEND | SECRBAC_MASK_NO_WRITE,
	ACL_APPEND    = SECRBAC_MASK_APPEND    | SECRBAC_MASK_WRITE,
	ACL_LINK      = SECRBAC_MASK_LINK      | SECRBAC_MASK_ADMINISTER,
	ACL_DELETE    = SECRBAC_MASK_DELETE    | SECRBAC_MASK_ADMINISTER,
	ACL_RENAME    = SECRBAC_MASK_RENAME    | SECRBAC_MASK_ADMINISTER,
};


static secmac_d secrbac_rbac_hook (
		const secmac_data_t* sub_attr,
		const secmac_data_t* res_attr,
		uint16_t secmac_op)
{
	uint32_t  nroles,acls,i,j;
	const uint32_t* roles;
	const uint64_t* acl;
	uint32_t  mask = 0;
	secrbac_entry_t entry;
	
	nroles = sub_attr[0].size/sizeof(uint32_t);
	roles  = sub_attr[0].ptr;
	acl    = res_attr[0].ptr;
	acls   = res_attr[0].size/sizeof(uint64_t);
	
	for(i=0;i<acls;++i){
		entry = secrbac_decode(acl[i]);
		for(j=0;j<nroles;++j){
			if( roles[i] != entry.rid ) continue;
			mask |= entry.mask;
			break;
		}
	}
	if( (secmac_op & SMOP_WRITE ) &&  ( mask & SECRBAC_MASK_NO_WRITE ) ) return secmac_DENY;
	if( (secmac_op & SMOP_APPEND) &&  ( mask & ACL_NO_APPEND ) ) return secmac_DENY;
	if( (secmac_op & SMOP_READ  ) &&  ( mask & SECRBAC_MASK_NO_READ ) ) return secmac_DENY;
	if( (secmac_op & SMOP_EXEC  ) &&  ( mask & SECRBAC_MASK_NO_EXECUTE ) ) return secmac_DENY;
	
	if( (secmac_op & SMOP_WRITE ) && !( mask & SECRBAC_MASK_WRITE ) ) return secmac_NONE;
	if( (secmac_op & SMOP_APPEND) && !( mask & ACL_APPEND ) ) return secmac_NONE;
	if( (secmac_op & SMOP_READ  ) && !( mask & SECRBAC_MASK_READ ) ) return secmac_NONE;
	if( (secmac_op & SMOP_EXEC  ) && !( mask & SECRBAC_MASK_EXECUTE ) ) return secmac_NONE;
	
	if( (secmac_op & SMOP_ADMIN ) && !( mask & SECRBAC_MASK_ADMINISTER ) ) return secmac_NONE;
	if( (secmac_op & SMOP_LINK  ) && !( mask & ACL_LINK ) ) return secmac_NONE;
	if( (secmac_op & SMOP_DELETE) && !( mask & ACL_DELETE ) ) return secmac_NONE;
	if( (secmac_op & SMOP_RENAME) && !( mask & ACL_RENAME ) ) return secmac_NONE;
	if( secmac_op & SMOP_UNSUP ) return secmac_NONE;
	
	return secmac_ALLOW;
}


/*
 * RBAC resource hook.
 */
const secmac_res_hook_t secrbac_res_hook={
	.subject_attrs = subject_attrs,
	.resource_attrs = resource_attrs,
	.OP_hook = secrbac_rbac_hook
};


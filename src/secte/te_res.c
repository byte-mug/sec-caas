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
#include <secte/te_res.h>
#include <secte/aclfmt.h>

static const char* const subject_attrs[] = {
	SECTE_SUBJECT,
};

static const char* const resource_attrs[] = {
	SECTE_RESOURCE,
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
	SMOP_NO_RWX = ~ (SMOP_APPEND|SMOP_WRITE|SMOP_READ|SMOP_EXEC),
};

enum {
	ACL_GRANT_APPEND = SECTE_MASK_GRANT_APPEND | SECTE_MASK_GRANT_WRITE,
	ACL_APPEND       = SECTE_MASK_APPEND       | SECTE_MASK_WRITE         | SECTE_MASK_GRANT_APPEND | SECTE_MASK_GRANT_WRITE,
	ACL_ADMINISTER   = SECTE_MASK_ADMINISTER   | SECTE_MASK_GRANT_ADMINISTER,
	ACL_LINK         = SECTE_MASK_LINK         | SECTE_MASK_ADMINISTER    | SECTE_MASK_GRANT_LINK   | SECTE_MASK_GRANT_ADMINISTER,
	ACL_DELETE       = SECTE_MASK_DELETE       | SECTE_MASK_ADMINISTER    | SECTE_MASK_GRANT_DELETE | SECTE_MASK_GRANT_ADMINISTER,
	ACL_RENAME       = SECTE_MASK_RENAME       | SECTE_MASK_ADMINISTER    | SECTE_MASK_GRANT_RENAME | SECTE_MASK_GRANT_ADMINISTER,
	ACL_WRITE        = SECTE_MASK_WRITE        | SECTE_MASK_GRANT_WRITE,
	ACL_READ         = SECTE_MASK_READ         | SECTE_MASK_GRANT_READ,
	ACL_EXECUTE      = SECTE_MASK_EXECUTE      | SECTE_MASK_GRANT_EXECUTE,
};


static secmac_d secte_te_hook (
		const secmac_data_t* sub_attr,
		const secmac_data_t* res_attr,
		uint16_t secmac_op)
{
	uint32_t  ntypes,acls,i,j;
	const uint32_t* types;
	const uint64_t* acl;
	uint32_t  mask = 0;
	secte_entry_t entry;
	secmac_d allow, deny;
	
	allow = secmac_ALLOW;
	deny  = secmac_NONE;
	
	ntypes = res_attr[0].size/sizeof(uint32_t);
	types  = res_attr[0].ptr;
	acl    = sub_attr[0].ptr;
	acls   = sub_attr[0].size/sizeof(uint64_t);
	
	/*
	 * If the Resource has no type, don't do anything.
	 */
	if( ntypes < 1 ) return secmac_NONE;
	
	for(i=0;i<acls;++i){
		entry = secte_decode(acl[i]);
		for(j=0;j<ntypes;++j){
			if( types[i] != entry.tid ) continue;
			mask |= entry.mask;
			break;
		}
	}
	
	/*
	 * Check explicit grants.
	 * If any explicite grant is not given, then do not explicitely ALLOW.
	 */
	if( (secmac_op & SMOP_WRITE ) && !( mask & SECTE_MASK_GRANT_WRITE      ) ) allow = secmac_NONE;
	if( (secmac_op & SMOP_APPEND) && !( mask & ACL_GRANT_APPEND            ) ) allow = secmac_NONE;
	if( (secmac_op & SMOP_READ  ) && !( mask & SECTE_MASK_GRANT_READ       ) ) allow = secmac_NONE;
	if( (secmac_op & SMOP_EXEC  ) && !( mask & SECTE_MASK_GRANT_EXECUTE    ) ) allow = secmac_NONE;
	if( (secmac_op & SMOP_ADMIN ) && !( mask & SECTE_MASK_GRANT_ADMINISTER ) ) allow = secmac_NONE;
	if( (secmac_op & SMOP_LINK  ) && !( mask & SECTE_MASK_GRANT_LINK       ) ) allow = secmac_NONE;
	if( (secmac_op & SMOP_DELETE) && !( mask & SECTE_MASK_GRANT_DELETE     ) ) allow = secmac_NONE;
	if( (secmac_op & SMOP_RENAME) && !( mask & SECTE_MASK_GRANT_RENAME     ) ) allow = secmac_NONE;
	if(  secmac_op & SMOP_NO_RWX  ) allow = secmac_NONE;
	
	/*
	 * Check basic permissions.
	 * If any basic permission is not given, then DENY.
	 */
	if( (secmac_op & SMOP_WRITE ) && !( mask & ACL_WRITE      ) ) deny = secmac_DENY;
	if( (secmac_op & SMOP_APPEND) && !( mask & ACL_APPEND     ) ) deny = secmac_DENY;
	if( (secmac_op & SMOP_READ  ) && !( mask & ACL_READ       ) ) deny = secmac_DENY;
	if( (secmac_op & SMOP_EXEC  ) && !( mask & ACL_EXECUTE    ) ) deny = secmac_DENY;
	
	if( (secmac_op & SMOP_ADMIN ) && !( mask & ACL_ADMINISTER ) ) deny = secmac_DENY;
	if( (secmac_op & SMOP_LINK  ) && !( mask & ACL_LINK       ) ) deny = secmac_DENY;
	if( (secmac_op & SMOP_DELETE) && !( mask & ACL_DELETE     ) ) deny = secmac_DENY;
	if( (secmac_op & SMOP_RENAME) && !( mask & ACL_RENAME     ) ) deny = secmac_DENY;
	
	return secmac_reduce(allow,deny);
}


/*
 * Type Enforcement (TE) Resource Hook.
 */
const secmac_res_hook_t secte_res_hook={
	.subject_attrs = subject_attrs,
	.resource_attrs = resource_attrs,
	.OP_hook = secte_te_hook
};


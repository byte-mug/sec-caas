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
#include <secacl/secacl.h>
#include <secacl/aclfmt.h>
#include <secmac/posix.h>

static const char* const subject_attrs[] = {
	SECMAC_POSIX_CRED,
	SECMAC_POSIX_GROUPS,
};

static const char* const resource_attrs[] = {
	SECACL_ACL_ENTRY,
};

enum {
	SMOP_APPEND = SECMAC_OP_APPEND,
	SMOP_WRITE  = SECMAC_OP_WRITE,
	SMOP_READ   = SECMAC_OP_READ,
	SMOP_EXEC   = SECMAC_OP_EXEC,
	SMOP_ADMIN  = SECMAP_OP_CH_MODE|SECMAP_OP_CH_OWNER|SECMAP_OP_CH_ATTRIB|SECMAP_OP_WRITEMETA,
	SMOP_LINK   = SECMAP_OP_LINK,
	SMOP_DELETE = SECMAC_OP_DELETE,
	SMOP_RENAME = SECMAP_OP_RENAME,
};

enum {
	SMOP_UNSUP = ~ (SMOP_APPEND|SMOP_WRITE|SMOP_READ|SMOP_EXEC|SMOP_ADMIN),
};

enum {
	ACL_NO_APPEND = SECACL_MASK_NO_APPEND | SECACL_MASK_NO_WRITE,
	ACL_APPEND    = SECACL_MASK_APPEND    | SECACL_MASK_WRITE,
	ACL_LINK      = SECACL_MASK_LINK      | SECACL_MASK_ADMINISTER,
	ACL_DELETE    = SECACL_MASK_DELETE    | SECACL_MASK_ADMINISTER,
	ACL_RENAME    = SECACL_MASK_RENAME    | SECACL_MASK_ADMINISTER,
};

static secmac_d secmac_dac_hook (
		const secmac_data_t* sub_attr,
		const secmac_data_t* res_attr,
		uint16_t secmac_op)
{
	const secmac_posix_cred* cred;
	
	uint32_t  ngroups,acls,i,j;
	const uint32_t* groups;
	const uint64_t* acl;
	uint16_t  mask = 0;
	unsigned found;
	secacl_entry_t entry;
	
	/*
	 * Make sure, that we have a valid credential and a valid stat.
	 */
	if( sub_attr[0].size < sizeof(secmac_posix_cred) ) return secmac_NONE;
	
	cred    = sub_attr[0].ptr;
	ngroups = sub_attr[1].size/sizeof(uint32_t);
	groups  = sub_attr[1].ptr;
	acl  = res_attr[0].ptr;
	acls = res_attr[0].size/sizeof(uint64_t);
	
	for(i=0;i<acls;++i){
		entry = secacl_decode(acl[i]);
		found = 0;
		switch(entry.type){
		case SECACL_TYPE_USER:
		case SECACL_TYPE_INV_USER:
			if( cred->uid == entry.xid ) found = 1;
			break;
		case SECACL_TYPE_GROUP:
		case SECACL_TYPE_INV_GROUP:
			if( cred->gid == entry.xid ) found = 1;
			else for(j=0;j<ngroups;++j){
				if( groups[i] != entry.xid ) continue;
				found = 1;
				break;
			}
			break;
		case SECACL_TYPE_OTHER:
		case SECACL_TYPE_INV_OTHER:
			found = 1;
			break;
		}
		switch(entry.type){
		case SECACL_TYPE_INV_USER:
		case SECACL_TYPE_INV_GROUP:
		case SECACL_TYPE_INV_OTHER:
			found = !found;
		}
		if(found) mask |= entry.mask;
	}
	if( (secmac_op & SMOP_WRITE ) && ( mask & SECACL_MASK_NO_WRITE ) ) return secmac_DENY;
	if( (secmac_op & SMOP_APPEND) && ( mask & ACL_NO_APPEND ) ) return secmac_DENY;
	if( (secmac_op & SMOP_READ  ) && ( mask & SECACL_MASK_NO_READ ) ) return secmac_DENY;
	if( (secmac_op & SMOP_EXEC  ) && ( mask & SECACL_MASK_NO_EXECUTE ) ) return secmac_DENY;
	
	if( (secmac_op & SMOP_WRITE ) && !( mask & SECACL_MASK_WRITE ) ) return secmac_NONE;
	if( (secmac_op & SMOP_APPEND) && !( mask & ACL_APPEND ) ) return secmac_NONE;
	if( (secmac_op & SMOP_READ  ) && !( mask & SECACL_MASK_READ ) ) return secmac_NONE;
	if( (secmac_op & SMOP_EXEC  ) && !( mask & SECACL_MASK_EXECUTE ) ) return secmac_NONE;
	
	if( (secmac_op & SMOP_ADMIN ) && !( mask & SECACL_MASK_ADMINISTER ) ) return secmac_NONE;
	if( (secmac_op & SMOP_LINK  ) && !( mask & ACL_LINK ) ) return secmac_NONE;
	if( (secmac_op & SMOP_DELETE) && !( mask & ACL_DELETE ) ) return secmac_NONE;
	if( (secmac_op & SMOP_RENAME) && !( mask & ACL_RENAME ) ) return secmac_NONE;
	
	return secmac_ALLOW;
}

/*
 * Rich POSIX-similar Access Control List implementation.
 */
const secmac_res_hook_t secacl_res_acl = {
	.subject_attrs = subject_attrs,
	.resource_attrs = resource_attrs,
	.OP_hook = secmac_dac_hook
};

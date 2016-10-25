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
#include <secrbig/secrbig.h>
#include <secrbig/aclfmt.h>

static const char* const subject_attrs[] = {
	SECRBIG_RING,
};

static const char* const resource_attrs[] = {
	SECRBIG_RING,
	SECRBIG_ACL,
};

enum {
	SMOP_ADMINISTER = SECMAP_OP_CH_MODE | SECMAP_OP_CH_OWNER | SECMAP_OP_CH_ATTRIB
		| SECMAP_OP_LINK | SECMAP_OP_RENAME | SECMAC_OP_DELETE,
};

static secmac_d secrbig_res_check (
		const secmac_data_t* sub_attr,
		const secmac_data_t* res_attr,
		uint16_t secmac_op)
{
	uint32_t acls,i;
	uint32_t subject_ring;
	uint32_t resource_ring;
	const uint64_t *acl;
	secrbig_entry_t entry;
	
	if(sub_attr[0].size < sizeof(uint32_t)) return secmac_NONE;
	if(res_attr[0].size < sizeof(uint32_t)) return secmac_NONE;
	
	subject_ring  = *((const uint32_t *)sub_attr[1].ptr);
	resource_ring = *((const uint32_t *)res_attr[1].ptr);
	
	acl  = res_attr[1].ptr;
	acls = res_attr[1].size/sizeof(uint64_t);
	
	if(subject_ring <= resource_ring) return secmac_NONE;
	
	/*
	 * This loop zeroes out every action flag, that is being permitted by the ACL.
	 */
	for(i=0;i<acls;++i){
		entry = secrbig_decode(acl[i]);
		if( subject_ring > entry.ring )continue;
		
		if(entry.mask & SECRBIG_MASK_APPEND     ) secmac_op &= ~SECMAC_OP_APPEND;
		if(entry.mask & SECRBIG_MASK_READ       ) secmac_op &= ~SECMAC_OP_READ;
		if(entry.mask & SECRBIG_MASK_WRITE      ) secmac_op &= ~SECMAC_OP_WRITE;
		if(entry.mask & SECRBIG_MASK_EXECUTE    ) secmac_op &= ~SECMAC_OP_EXEC;
		
		if(entry.mask & SECRBIG_MASK_WRITEMETA  ) secmac_op &= ~SECMAP_OP_WRITEMETA;
		if(entry.mask & SECRBIG_MASK_CONNECT    ) secmac_op &= ~SECMAP_OP_CONNECT;
		if(entry.mask & SECRBIG_MASK_ACCEPT     ) secmac_op &= ~SECMAP_OP_ACCEPT;
		
		if(entry.mask & SECRBIG_MASK_ADMINISTER ) secmac_op &= ~SMOP_ADMINISTER;
		if(entry.mask & SECRBIG_MASK_LINK       ) secmac_op &= ~SECMAP_OP_LINK;
		if(entry.mask & SECRBIG_MASK_DELETE     ) secmac_op &= ~SECMAC_OP_DELETE;
		if(entry.mask & SECRBIG_MASK_RENAME     ) secmac_op &= ~SECMAP_OP_RENAME;
	}
	
	/*
	 * If the secmac_op vector contains no action flag, access isn't denied.
	 */
	if( 0 == secmac_op ) return secmac_NONE;
	return secmac_DENY;
}

/*
 * RBIG implementation.
 */
const secmac_res_hook_t secrbig_res_hook={
	.subject_attrs = subject_attrs,
	.resource_attrs = resource_attrs,
	.OP_hook = secrbig_res_check
};


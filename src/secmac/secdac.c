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
#include <secmac/resource_dac.h>
#include <secmac/posix.h>

static const char* const subject_attrs[] = {
	SECMAC_POSIX_CRED,
	SECMAC_POSIX_GROUPS,
};

static const char* const resource_attrs[] = {
	SECMAC_POSIX_STAT,
};

enum {
	SMOP_WRITE = SECMAC_OP_WRITE|SECMAC_OP_APPEND|SECMAC_OP_DELETE|SECMAP_OP_RENAME|SECMAP_OP_WRITEMETA,
	SMOP_READ = SECMAC_OP_READ,
	SMOP_EXEC = SECMAC_OP_EXEC,
	SMOP_ADMIN = SECMAP_OP_CH_MODE|SECMAP_OP_CH_OWNER|SECMAP_OP_WRITEMETA|SECMAP_OP_LINK,
};

enum {
	SMOP_UNSUP = ~ (SMOP_WRITE|SMOP_READ|SMOP_EXEC|SMOP_ADMIN),
};

static secmac_d secmac_dac_hook (
		const secmac_data_t* sub_attr,
		const secmac_data_t* res_attr,
		uint16_t secmac_op)
{
	const secmac_posix_cred* cred;
	const secmac_posix_stat* stat;
	uint16_t filtermode = SECDAC_S_IRWXO;
	uint32_t  ngroups,i;
	const uint32_t* groups;
	
	/*
	 * Make sure, that we have a valid credential and a valid stat.
	 */
	if( sub_attr[0].size < sizeof(secmac_posix_cred) ) return secmac_NONE;
	if( res_attr[0].size < sizeof(secmac_posix_stat) ) return secmac_NONE;
	
	cred    = sub_attr[0].ptr;
	stat    = res_attr[0].ptr;
	ngroups = sub_attr[1].size/sizeof(uint32_t);
	groups  = sub_attr[1].ptr;
	
	/*
	 * If the subject is OWNER.
	 */
	if( cred->uid == stat->st_uid ) filtermode |= SECDAC_S_IRWXU;
	
	/*
	 * If the subject is GROUP MEMBER.
	 */
	if( cred->gid == stat->st_gid ) filtermode |= SECDAC_S_IRWXG;
	/*
	 * Else, look in the GROUPS-list.
	 */
	else for(i=0;i<ngroups;++i){
		/*
		 * Skip groups, that are not the group that was meant.
		 */
		if( groups[i] != stat->st_gid ) continue;
		
		/*
		 * We found the group that was meant.
		 */
		filtermode |= SECDAC_S_IRWXG;
		break;
	}
	/*
	 * Apply the mask to 'stat->st_mode' and store the result in 'filtermode'.
	 */
	filtermode &= stat->st_mode;
	
	/*
	 * Unsupported actions cannot be allowed.
	 */
	if( secmac_op & SMOP_UNSUP ) return secmac_NONE;
	
	/*
	 * Check Read, Write and Execute bits, when 'secmac_op' requests them.
	 */
	if( (secmac_op & SMOP_READ) && !(filtermode & SECDAC_S_IRALL) ) return secmac_NONE;
	if( (secmac_op & SMOP_WRITE) && !(filtermode & SECDAC_S_IWALL) ) return secmac_NONE;
	if( (secmac_op & SMOP_EXEC) && !(filtermode & SECDAC_S_IXALL) ) return secmac_NONE;
	
	/*
	 * Some functions may only be done by the Owner. Check them.
	 */
	if( (secmac_op & SMOP_ADMIN) && ( cred->uid != stat->st_uid )) return secmac_NONE;
	
	return secmac_ALLOW;
}

/*
 * Default POSIX-like Discretionary Access Control implementation.
 */
const secmac_res_hook_t secmac_res_dac = {
	.subject_attrs = subject_attrs,
	.resource_attrs = resource_attrs,
	.OP_hook = secmac_dac_hook
};

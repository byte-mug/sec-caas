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
#include <secmls/integrity.h>

static const char* const subject_attrs[] = {
	SECMLS_INTEGRITY_LEVEL,
};

static const char* const resource_attrs[] = {
	SECMLS_INTEGRITY_LEVEL,
};

/*
 * SMOP_READ and SMOP_WRITE are defined with the integrity in mind.
 *
 * SMOP_READ   : every operation on a possibly corrupted resource, that could
 *               result in a violation of integrity.
 * SMOP_WRITE : every operation on a resource that could corrupt it.
 */
enum {
	SMOP_READ  = SECMAC_OP_READ | SECMAC_OP_EXEC | SECMAP_OP_CONNECT | SECMAP_OP_ACCEPT,
	SMOP_WRITE = SECMAC_OP_WRITE | SECMAC_OP_APPEND  | SECMAP_OP_WRITEMETA
		| SECMAP_OP_CH_MODE | SECMAP_OP_CH_OWNER | SECMAP_OP_CH_ATTRIB
		| SECMAC_OP_DELETE | SECMAP_OP_RENAME | SECMAP_OP_LINK
	,
};

static secmac_d secmls_integrity_hook (
		const secmac_data_t* sub_attr,
		const secmac_data_t* res_attr,
		uint16_t secmac_op)
{
	uint32_t subject_level;
	uint32_t resource_level;
	
	if(sub_attr[0].size < sizeof(uint32_t)) return secmac_NONE;
	if(res_attr[0].size < sizeof(uint32_t)) return secmac_NONE;
	
	subject_level = *((const uint32_t *)sub_attr[0].ptr);
	resource_level = *((const uint32_t *)res_attr[0].ptr);
	
	/*
	 * The Simple Integrity Axiom
	 *   states that a subject at a given level of integrity must not read
	 *   an object at a lower integrity level (no read down).
	 */
	if(subject_level > resource_level){
		if(secmac_op & SMOP_READ) return secmac_DENY;
	}
	/*
	 * The * (star) Integrity Axiom states that a subject at a given level
	 *    of integrity must not write to any object at a higher level of
	 *    integrity (no write up).
	 */
	else if(subject_level < resource_level){
		if(secmac_op & SMOP_WRITE) return secmac_DENY;
	}
	
	return secmac_NONE;
}


/*
 * Partial Biba Integrity Model Implementation.
 *
 * Only the 'Simple Integrity Axiom' and the '* (star) Integrity Axiom' are implemented.
 *
 * The 'Invocation Property' is implemented using another module or hook.
 */
const secmac_res_hook_t secmls_integrity_res_hook={
	.subject_attrs = subject_attrs,
	.resource_attrs = resource_attrs,
	.OP_hook = secmls_integrity_hook
};


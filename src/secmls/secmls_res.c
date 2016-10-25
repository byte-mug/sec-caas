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
#include <secmls/secmls.h>

static const char* const subject_attrs[] = {
	SECMLS_LEVEL,
};

static const char* const resource_attrs[] = {
	SECMLS_LEVEL,
};

/*
 * SMOP_READ and SMOP_WRITE are defined with the flow of information in mind (Secrecy).
 */
enum {
	SMOP_READ  = SECMAC_OP_READ   | SECMAC_OP_EXEC,
	SMOP_WRITE = SECMAC_OP_WRITE  | SECMAC_OP_APPEND  | SECMAP_OP_WRITEMETA,
};

static secmac_d secmls_mls_hook (
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
	 * The Simple Security Property:
	 *   a subject at a given security level may not read an object at a
	 *   higher security level (no read-up).
	 */
	if(subject_level < resource_level){
		if(secmac_op & SMOP_READ) return secmac_DENY;
	}
	/*
	 * The Star-property (read "star"-property):
	 *   a subject at a given security level must not write to any object
	 *   at a lower security level (no write-down).
	 */
	else if(subject_level > resource_level){
		if(secmac_op & SMOP_WRITE) return secmac_DENY;
	}
	
	return secmac_NONE;
}


/*
 * Partial Bell-LaPadula model Implementation.
 *
 * Only the 'Simple Security Property' and the 'Star-property' are implemented.
 *
 * The 'Discretionary Security Property' is implemented using another module.
 */
const secmac_res_hook_t secmls_res_hook={
	.subject_attrs = subject_attrs,
	.resource_attrs = resource_attrs,
	.OP_hook = secmls_mls_hook
};


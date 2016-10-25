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

static const char* const subject_attrs[] = {
	SECRBIG_RING,
};

static const char* const resource_attrs[] = {
	SECRBIG_RING,
};

static secmac_d secrbig_res_check (
		const secmac_data_t* sub_attr,
		const secmac_data_t* res_attr,
		uint16_t secmac_op)
{
	uint32_t subject_ring;
	uint32_t resource_ring;
	
	if(sub_attr[0].size < sizeof(uint32_t)) return secmac_NONE;
	if(res_attr[0].size < sizeof(uint32_t)) return secmac_NONE;
	
	subject_ring  = *((const uint32_t *)sub_attr[0].ptr);
	resource_ring = *((const uint32_t *)res_attr[0].ptr);
	
	if(subject_ring > resource_ring) return secmac_DENY;
	
	return secmac_NONE;
}

/*
 * RBIG implementation.
 */
const secmac_res_hook_t secrbig_res_hook={
	.subject_attrs = subject_attrs,
	.resource_attrs = resource_attrs,
	.OP_hook = secrbig_res_check
};


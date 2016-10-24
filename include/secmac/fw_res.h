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
#pragma once
#include <secfwstd/stdint.h>
#include <secmac/resource.h>

typedef struct secmac_res_module {
	/*
	 * A list of indeces, refering the SUBJECT attributes needed for this
	 * security hook.
	 */
	uint32_t        subject_attrs_len;
	const uint32_t* subject_attrs_list;
	
	/*
	 * A list of indeces, refering the RESOURCE attributes needed for this
	 * security hook.
	 */
	uint32_t        resource_attrs_len;
	const uint32_t* resource_attrs_list;
	
	/* A reference to the security decision hook. */
	const secmac_res_hook_t* hook;
} secmac_res_module_t;

typedef struct secmac_res_fw {
	/*
	 * A list of strings, representing the SUBJECT attributes needed for
	 * the security decision modules.
	 */
	uint32_t           subject_attrs_len;
	const char* const* subject_attrs_list;
	
	/*
	 * A list of strings, representing the RESOURCE attributes needed for
	 * the security decision modules.
	 */
	uint32_t           resource_attrs_len;
	const char* const* resource_attrs_list;
	
	/*
	 * A list of security decision modules.
	 */
	uint32_t              modules_len;
	secmac_res_module_t** modules_list;
} secmac_res_fw_t;

secmac_res_fw_t *secmac_res_new();
void secmac_res_destroy(secmac_res_fw_t* res);
secmac_res_fw_t* secmac_res_clone(const secmac_res_fw_t* res);

int secmac_res_add_hook(secmac_res_fw_t* res, const secmac_res_hook_t* hook);
/* void secmac_res_remove_hook(secmac_res_fw_t* res, const secmac_res_hook_t* hook); */

/*
 * This function checks the permission of a SUBJECT to access a RESOURCE.
 * The function is thread-safe.
 */
secmac_d secmac_res_check_op(
		const secmac_res_fw_t* framework,
		const secmac_data_t* sub_attr,
		const secmac_data_t* res_attr,
		uint16_t secmac_op);



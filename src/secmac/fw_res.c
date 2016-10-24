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

#include <secfwstd/stdmem.h>
#include <secmac/fw_res.h>
#include <stdio.h>

static uint32_t _secmac_getsize(const char* const* arr){
	uint32_t s = 0;
	while(*arr) arr++,s++;
	return s;
}
static uint32_t _secmac_find(const char* const* arr,uint32_t size,const char* str){
	uint32_t i;
	for(i=0;i<size;++i){
		if(!sec_strcmp(arr[i],str)) return i;
	}
	return size;
}

secmac_res_fw_t *secmac_res_new(){
	secmac_res_fw_t* res = sec_malloc(sizeof(secmac_res_fw_t));
	sec_bzero(res,sizeof(secmac_res_fw_t));
	return res;
}
void secmac_res_destroy(secmac_res_fw_t* res){
	sec_free(res);
}
secmac_res_fw_t* secmac_res_clone(const secmac_res_fw_t* res){
	return 0;
}

int secmac_res_add_hook(secmac_res_fw_t* res, const secmac_res_hook_t* hook){
	uint32_t nsub,nres,msub,mres,osub,ores,i,j;
	const char** add_sub;
	const char** add_res;
	const char** newptr;
	secmac_res_module_t* module;
	secmac_res_module_t** mptr;
	uint32_t* idx_sub;
	uint32_t* idx_res;
	
	nsub = res->subject_attrs_len;
	nres = res->resource_attrs_len;
	msub = _secmac_getsize(hook->subject_attrs);
	mres = _secmac_getsize(hook->resource_attrs);
	osub = 0;
	ores = 0;
	
	module  = sec_malloc(sizeof(secmac_res_module_t));
	add_sub = sec_malloc(msub * sizeof(void*));
	add_res = sec_malloc(mres * sizeof(void*));
	idx_sub = sec_malloc(msub * sizeof(uint32_t));
	idx_res = sec_malloc(mres * sizeof(uint32_t));
	if(
		(!module)||
		(!add_sub)||
		(!add_res)||
		(!idx_sub)||
		(!idx_res)
	) goto ERROR;
	
	for(i=0;i<msub;++i){
		j = _secmac_find(res->subject_attrs_list,nsub,hook->subject_attrs[i]);
		if(j<nsub){
			idx_sub[i] = j;
			continue;
		}
		idx_sub[i] = osub+nsub;
		add_sub[osub] = hook->subject_attrs[i];
		osub++;
	}
	for(i=0;i<mres;++i){
		j = _secmac_find(res->resource_attrs_list,nsub,hook->resource_attrs[i]);
		if(j<nres){
			idx_res[i] = j;
			continue;
		}
		idx_res[i] = ores+nres;
		add_res[ores] = hook->resource_attrs[i];
		ores++;
	}
	if(osub>0){
		newptr = (const char**)sec_realloc((void*)(res->subject_attrs_list),(osub+nsub)*sizeof(void*));
		if(!newptr)goto ERROR;
		res->subject_attrs_list = newptr;
		sec_memcpy(&(newptr[nsub]),add_sub,osub*sizeof(void*));
	}
	if(ores>0){
		newptr = (const char**)sec_realloc((void*)(res->resource_attrs_list),(ores+nres)*sizeof(void*));
		if(!newptr)goto ERROR;
		res->resource_attrs_list = newptr;
		sec_memcpy(&(newptr[nres]),add_res,ores*sizeof(void*));
	}
	mptr = sec_realloc(res->modules_list,(res->modules_len+1)*sizeof(void*));
	if(!mptr) goto ERROR;
	res->modules_list = mptr;
	mptr[res->modules_len]      = module;
	res->modules_len++;
	
	module->subject_attrs_len   = msub;
	module->resource_attrs_len  = mres;
	module->subject_attrs_list  = idx_sub;
	module->resource_attrs_list = idx_res;
	module->hook                = hook;
	res->subject_attrs_len      = nsub+osub;
	res->resource_attrs_len     = nres+ores;
	
	
	sec_free(add_sub);
	sec_free(add_res);
	
	return 1;
ERROR:
	if(module) sec_free(module);
	if(add_sub)sec_free(add_sub);
	if(add_res)sec_free(add_res);
	if(idx_sub)sec_free(idx_sub);
	if(idx_res)sec_free(idx_res);
	return 0;
}

/*
 * This function checks the permission of a SUBJECT to access a RESOURCE.
 * The function is thread-safe.
 */
secmac_d secmac_res_check_op(
		const secmac_res_fw_t* framework,
		const secmac_data_t* sub_attr,
		const secmac_data_t* res_attr,
		uint16_t secmac_op)
{
	unsigned i,j;
	secmac_d result = secmac_NONE;
	secmac_data_t
	subs[framework->subject_attrs_len],
	ress[framework->resource_attrs_len];
	secmac_res_module_t* module;
	
	for(i=0;i<(framework->modules_len);++i){
		module = framework->modules_list[i];
		for(j=0;j<(module->subject_attrs_len);++j)
			subs[j]=sub_attr[module->subject_attrs_list[j]];
		for(j=0;j<(module->resource_attrs_len);++j)
			ress[j]=res_attr[module->resource_attrs_list[j]];
		result = secmac_reduce(result,
			module->hook->OP_hook(subs,ress,secmac_op)
		);
	}
	return result;
}


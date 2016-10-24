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
#include <testfw/test_res.h>

secmac_data_t* testfw_getdata(secmac_data_entry_t* entries,uint32_t nentries,const char* const* attrs,uint32_t nattrs){
	uint32_t i,j;
	secmac_data_t* result = sec_malloc(nattrs * sizeof(void*));
	
	if(!result)return 0;
	sec_bzero(result,nattrs * sizeof(void*));
	for(i=0;i<nattrs;++i){
		for(j=0;j<nentries;++j){
			if(sec_strcmp(entries[j].name,attrs[i]))continue;
			result[i] = entries[j].data;
			break;
		}
	}
	return result;
}



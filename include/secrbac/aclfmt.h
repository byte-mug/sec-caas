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

typedef struct{
	uint32_t rid;
	uint32_t mask;
} secrbac_entry_t;

#define _SECRBAC_CAST(num)  ((uint64_t)(num))
#define SECRBAC_ENTRY(xid,perms)  (_SECRBAC_CAST(xid<<32)|_SECRBAC_CAST(perms) )

static inline secrbac_entry_t secrbac_decode(uint64_t entry){
	return (secrbac_entry_t){ (uint32_t)(entry>>32), (uint32_t)(entry&0xffffffffu)  };
}

#define SECRBAC_MASK_APPEND     0x0008
#define SECRBAC_MASK_READ       0x0004
#define SECRBAC_MASK_WRITE      0x0002
#define SECRBAC_MASK_EXECUTE    0x0001

#define SECRBAC_MASK_NO_APPEND  0x0080
#define SECRBAC_MASK_NO_READ    0x0040
#define SECRBAC_MASK_NO_WRITE   0x0020
#define SECRBAC_MASK_NO_EXECUTE 0x0010

#define SECRBAC_MASK_ADMINISTER 0x0100
#define SECRBAC_MASK_LINK       0x0200
#define SECRBAC_MASK_DELETE     0x0400
#define SECRBAC_MASK_RENAME     0x0800


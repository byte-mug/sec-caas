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
	uint32_t xid;
	uint16_t type;
	uint16_t mask;
} secacl_entry_t;

#define _SECACL_CAST(num)  ((uint64_t)(num))
#define SECACL_ENTRY(xid,type,perms)  (_SECACL_CAST(xid<<32)|_SECACL_CAST(type<<16)|_SECACL_CAST(perms))

static inline secacl_entry_t secacl_decode(uint64_t entry){
	return (secacl_entry_t){ (uint32_t)(entry>>32), (uint16_t)((entry>>16)&0xffff), (uint16_t)(entry&0xffff)  };
}

#define SECACL_ACL_ENTRY "SECACL.ACL"

#define SECACL_TYPE_USER       0x0001
#define SECACL_TYPE_GROUP      0x0002
#define SECACL_TYPE_OTHER      0x0004  /* Other = All. */

/* Like the above but */
#define SECACL_TYPE_INV_USER   0x0010
#define SECACL_TYPE_INV_GROUP  0x0020
#define SECACL_TYPE_INV_OTHER  0x0040


#define SECACL_MASK_APPEND     0x0008
#define SECACL_MASK_READ       0x0004
#define SECACL_MASK_WRITE      0x0002
#define SECACL_MASK_EXECUTE    0x0001

#define SECACL_MASK_NO_APPEND  0x0080
#define SECACL_MASK_NO_READ    0x0040
#define SECACL_MASK_NO_WRITE   0x0020
#define SECACL_MASK_NO_EXECUTE 0x0010

#define SECACL_MASK_ADMINISTER 0x0100
#define SECACL_MASK_LINK       0x0200
#define SECACL_MASK_DELETE     0x0400
#define SECACL_MASK_RENAME     0x0800

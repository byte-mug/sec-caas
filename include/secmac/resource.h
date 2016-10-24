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
#include <secmac/decision.h>

typedef struct {
	const void* ptr;
	uint32_t    size;
} secmac_data_t;

enum{
	SECMAC_OP_READ      = 0x0001,
	SECMAC_OP_WRITE     = 0x0002,
	SECMAC_OP_EXEC      = 0x0004,
	SECMAC_OP_APPEND    = 0x0008,
	SECMAC_OP_DELETE    = 0x0010, /* e.g. unlink() */
	SECMAP_OP_RENAME    = 0x0020, /* e.g. rename() */
	SECMAP_OP_LINK      = 0x0040, /* e.g. creating an hardlink. */
	SECMAP_OP_SEND      = 0x0080, /* Send (socket-like resources) */
	SECMAP_OP_RECEIVE   = 0x0100, /* Receive (socket-like resources) */
	SECMAP_OP_CH_MODE   = 0x0200, /* Change Mode in POSIX_STAT. */
	SECMAP_OP_CH_OWNER  = 0x0400, /* Change Owner in POSIX_STAT.*/
	SECMAP_OP_CH_ATTRIB = 0x0800, /* Change SECMAC Attributes. */
	SECMAP_OP_WRITEMETA = 0x1000, /* Write Metadata (e.g. utime()). */
};

typedef struct secmac_res_hook {
	/*
	 * A NULL-terminated list of strings, representing the SUBJECT
	 * attributes needed for this security hook.
	 */
	const char* const* subject_attrs;
	/*
	 * A NULL-terminated list of strings, representing the RESOURCE
	 * attributes needed for this security hook.
	 */
	const char* const* resource_attrs;
	
	/*
	 * A hook operation, that checks the permission of a SUBJECT to access
	 * a RESOURCE. Should default to secmac_NONE.
	 */
	secmac_d (*OP_hook) (
		const secmac_data_t* sub_attr,
		const secmac_data_t* res_attr,
		uint16_t secmac_op);
} secmac_res_hook_t ;


#define SECMAC_POSIX_CRED "POSIX.CRED"
typedef struct{
	uint32_t uid,gid;
} secmac_posix_cred;

/*
 * Some POSIX OSes offer the possibility to inherit multiple groups at the same
 * time (such as Linux, System V, BSD). When available, (and requestable) they
 * can be used.
 */
#define SECMAC_POSIX_GROUPS "POSIX.GROUPS"

#define SECMAC_POSIX_STAT "POSIX.STAT"
typedef struct{
	uint16_t st_mode;
	uint32_t st_uid;
	uint32_t st_gid;
	uint32_t st_rdev;
} secmac_posix_stat;


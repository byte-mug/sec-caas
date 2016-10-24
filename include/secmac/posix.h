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

/* POSIX file mode */
#define SECDAC_S_IFMT     0170000

#define SECDAC_S_IFSOCK   0140000   /* socket */
#define SECDAC_S_IFLNK    0120000   /* symbolic link */
#define SECDAC_S_IFREG    0100000   /* regular file */
#define SECDAC_S_IFBLK    0060000   /* block device */
#define SECDAC_S_IFDIR    0040000   /* directory */
#define SECDAC_S_IFCHR    0020000   /* character device */
#define SECDAC_S_IFIFO    0010000   /* FIFO */


#define SECDAC_S_ISUID     04000   /* set-user-ID bit */
#define SECDAC_S_ISGID     02000   /* set-group-ID bit (see below) */
#define SECDAC_S_ISVTX     01000   /* sticky bit (see below) */

#define SECDAC_S_IRWXU     00700   /* owner has read, write, and execute permission */
#define SECDAC_S_IRUSR     00400   /* owner has read permission */
#define SECDAC_S_IWUSR     00200   /* owner has write permission */
#define SECDAC_S_IXUSR     00100   /* owner has execute permission */

#define SECDAC_S_IRWXG     00070   /* group has read, write, and execute permission */
#define SECDAC_S_IRGRP     00040   /* group has read permission */
#define SECDAC_S_IWGRP     00020   /* group has write permission */
#define SECDAC_S_IXGRP     00010   /* group has execute permission */

#define SECDAC_S_IRWXO     00007   /* others (not in group) have read, write, and
                                    execute permission */
#define SECDAC_S_IROTH     00004   /* others have read permission */
#define SECDAC_S_IWOTH     00002   /* others have write permission */
#define SECDAC_S_IXOTH     00001   /* others have execute permission */

#define SECDAC_S_IRALL     00444   /* others have read permission */
#define SECDAC_S_IWALL     00222   /* others have write permission */
#define SECDAC_S_IXALL     00111   /* others have execute permission */


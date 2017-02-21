/*
	Copyright (C) 2015 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.

	This library may be distributed, used, and modified under the terms of
	BSD license:

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are
	met:

	1. Redistributions of source code must retain the above copyright
		 notice, this list of conditions and the following disclaimer.

	2. Redistributions in binary form must reproduce the above copyright
		 notice, this list of conditions and the following disclaimer in the
		 documentation and/or other materials provided with the distribution.

	3. Neither the name(s) of the above-listed copyright holder(s) nor the
		 names of its contributors may be used to endorse or promote products
		 derived from this software without specific prior written permission.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
	"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
	LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
	A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
	OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
	SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
	LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
	DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
	THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
	OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#ifndef _RHP_BFILTER_H_
#define _RHP_BFILTER_H_

#include <pthread.h>

typedef u_int64_t u64;
typedef u_int32_t u32;
typedef u_int16_t u16;
typedef u_int8_t   u8;


struct _rhp_bloom_filter_fdata {

#define RHP_BFLTR_FDATA_MAGIC		0xA8BD1E33
	u32 magic; // RHP_BFLTR_FDATA_MAGIC

#define RHP_BFLTR_FDATA_TAG_LEN	32
	u8 tag[RHP_BFLTR_FDATA_TAG_LEN];

	u32 max_num_of_elements;	// n
	double false_ratio;				// p
	u32 added_num;
	u32 collision_num;

	/* bitmap_data */
	/* salts_data */
};
typedef struct _rhp_bloom_filter_fdata	rhp_bloom_filter_fdata;


struct _rhp_bloom_filter {

	u8 tag[4]; // '#BLF'

	/*

	 Add a new element.

	   - bf_ctx: A pointer of the Bloom filter object returnd by rhp_bloom_filter_alloc()
	             or rhp_bloom_filter_alloc_ex().

	   - element_len: Length of 'element'. (Bytes)
	   - element: Added element value.

 	   Return Value: < 0: error.
	                 0  : 'element' doesn't exists and it was successfully added.
	                 1  : 'element' already exists or collison occurred.

	*/
	int (*add)(struct _rhp_bloom_filter* bf_ctx,size_t element_len,u8* element);


	/*

	 Check an element.

	   - bf_ctx: A pointer of the Bloom filter object returnd by rhp_bloom_filter_alloc()
	             or rhp_bloom_filter_alloc_ex().

	   - element_len: Length of 'element'. (Bytes)
	   - element: Checked element value.

 	   Return Value: < 0: error.
	                 0  : 'element' doesn't exists.
	                 1  : 'element' already exist or collison occurred.

	*/
	int (*contains)(struct _rhp_bloom_filter* bf_ctx,size_t element_len,u8* element);


	/*

	 Reset the Bloom filter object.

	   - bf_ctx: A pointer of the Bloom filter object returnd by rhp_bloom_filter_alloc()
	             or rhp_bloom_filter_alloc_ex().

	*/
	void (*reset)(struct _rhp_bloom_filter* bf_ctx);

	/*

	 Get the number of elements successfully added by bf_ctx->add().

	   - bf_ctx: A pointer of the Bloom filter object returnd by rhp_bloom_filter_alloc()
	             or rhp_bloom_filter_alloc_ex().

 	   Return Value: The number of added elements.
	*/
	u32 (*get_num)(struct _rhp_bloom_filter* bf_ctx);


	/*

	 Get the number of element's collisions (including false cases) by bf_ctx->add().

	   - bf_ctx: A pointer of the Bloom filter object returnd by rhp_bloom_filter_alloc()
	             or rhp_bloom_filter_alloc_ex().

 	   Return Value: The collision number of added elements.
	*/
	u32 (*get_collision_num)(struct _rhp_bloom_filter* bf_ctx);


	/*

	 Get a tag value specified by rhp_bloom_filter_alloc_ex().

	   - bf_ctx: A pointer of the Bloom filter object returnd by rhp_bloom_filter_alloc_ex().

 	   Return Value: A point of the tag value. This may be NULL if it was
 	                 not specified by rhp_bloom_filter_alloc_ex().
	*/
	u8* (*get_tag)(struct _rhp_bloom_filter* bf_ctx);


	/*

		Output info of the bloom filter object.

	   - bf_ctx: A pointer of the Bloom filter object returnd by rhp_bloom_filter_alloc()
	             or rhp_bloom_filter_alloc_ex().

	*/
	void (*dump)(struct _rhp_bloom_filter* bf_ctx);

	//
	// https://en.wikipedia.org/wiki/Bloom_filter
	//
	u32 max_num_of_elements;	// n
	double false_ratio;				// p
	u32 hashes_num;						// k
	u32 bitmap_len; 					// m (bits)
	u32 bitmap_bytes_len; 		// bytes m/8
	u8* bitmap;
	unsigned long* bitmap_updated_idxes;
	u32* salts;
	u32 added_num;
	u32 collision_num;

	char* file_path;


	//
	//
	// The followings are internally used values.
	//
	//

	pthread_mutex_t lock;

	int fd;
	rhp_bloom_filter_fdata* fdata;

	void* (*malloc)(size_t size);
	void (*mfree)(void *ptr);
	int (*random_bytes)(u8* buf,size_t buf_len);
};
typedef struct _rhp_bloom_filter	rhp_bloom_filter;


/*

	Allocate a bloom filter object.

	 - max_num_of_elements: The expected number of elements added into the
	                        filter. This value must be more than zero.

	 - false_ratio: False ratio like 0.001. This value must be more than
	                zero.


   Return Value: A pointer of the allocated Bloom filter object.

*/
extern rhp_bloom_filter* rhp_bloom_filter_alloc(
		u64 max_num_of_elements,
		double false_ratio);


/*

	Allocate or restore a bloom filter object.

	 - max_num_of_elements: The expected number of elements added into the
	                        filter. This value must be more than zero.

	 - false_ratio: False ratio like 0.001. This value must be more than
	                zero.

	 - file_path: The filter's config and state can be saved into a file by specifying
	 	 	 	 	 	 	  this arg. If the file exists, a bloom filter is restored by
	 	 	 	 	 	 	  reading it. If you want to discard the old config and state, free
	 	 	 	 	 	 	  the Bloom filter by rhp_bloom_filter_free(), just remove the file
	 	 	 	 	 	 	  by unlink() and then call this function again.
	              Also, you can use bf_ctx->reset() function to clear the old state
	              (The filter's config is not changed).

		- file_mode: File-mode attributes to create a new file specified by 'file_path'
		             if it doesn't exists. See man 2 open ('mode' arg) for more details.
								 [e.g.] (S_IRUSR | S_IWUSR | S_IXUSR)

		- dump_cb: A function pointer to output info of the bloom filter allocated by
		           this function. If NULL is specified, a default function is used.

		- malloc_cb: A function pointer to allocate a memory buffer.
		             If NULL is specified, a default function is used.

		- mfree_cb: A function pointer to free a memory buffer.
		            If NULL is specified, a default function is used.

		- random_bytes_cb: A function pointer to generate random numbers for salts
		                   This MUST generate cryptographically strong random bytes.
		                   If NULL is specified, a default function is used.

		- tag: Fixed length(RHP_BFLTR_FDATA_TAG_LEN). If 'file_path' is not specified,
		       this arg is ignored. You can get the tag value by bf_ctx->get_tag().


   Return Value: A pointer of the allocated Bloom filter object.

*/
extern rhp_bloom_filter* rhp_bloom_filter_alloc_ex(
		u64 max_num_of_elements,
		double false_ratio,
		const char* file_path,
		mode_t file_mode,
		void (*dump_cb)(struct _rhp_bloom_filter* bf_ctx),
		void* (*malloc_cb)(size_t size),
		void (*mfree_cb)(void *ptr),
		int (*random_bytes_cb)(u8* buf,size_t buf_len),
		u8* tag);


/*

	Free a bloom filter object.

	   - bf_ctx: A pointer of the Bloom filter object returnd by rhp_bloom_filter_alloc() or
	             rhp_bloom_filter_alloc_ex().

*/
extern void rhp_bloom_filter_free(rhp_bloom_filter* bf_ctx);

#endif // _RHP_BFILTER_H_

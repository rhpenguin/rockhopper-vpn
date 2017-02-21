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

/*

 	=== A simple Bloom Filter Lib ===

	[Bloom Filter]
	 - https://en.wikipedia.org/wiki/Bloom_filter

*/

#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#include "rhp_bfilter.h"


static void* _rhp_malloc_def(size_t size)
{
	return malloc(size);
}

static void _rhp_free_def(void *ptr)
{
	free(ptr);
}

// This MUST generate cryptographically strong random bytes.
static int _rhp_random_bytes_def(u8* buf,size_t buf_len)
{
	int fd = -1;
	size_t c = 0;
	int err = 0;

	fd = open("/dev/urandom", O_RDONLY);
	if( fd < 0 ){
		err = -errno;
		goto error;
	}

	while(c < buf_len){

	    ssize_t n = read(fd, buf + c, buf_len - c);
	    if(n < 0){
	  		err = -errno;
	  		goto error;
	    }

	    c += n;
	}

error:
	if( fd >= 0 ){
		close(fd);
	}

	return err;
}



//-----------------------------------------------------------------------------
//
// MurmurHash3 was written by Austin Appleby, and is placed in the public
// domain. The author hereby disclaims copyright to this source code.
//
// Note - The x86 and x64 versions do _not_ produce the same results, as the
// algorithms are optimized for their respective platforms. You can still
// compile and run any of them on any platform, but your performance with the
// non-native version will be less than optimal.
//
// https://code.google.com/p/smhasher/
//

static inline u_int32_t _rhp_murmur_hash3_rotl32(u_int32_t x, int8_t r)
{
  return (x << r) | (x >> (32 - r));
}
#define RHP_MURMUR_HASH3_ROTL32(x,y)     _rhp_murmur_hash3_rotl32(x,y)

static inline u_int32_t _rhp_murmur_hash3_getblock(const u_int32_t * p, int i)
{
  return p[i];
}

static inline u_int32_t _rhp_murmur_hash3_fmix(u_int32_t h)
{
  h ^= h >> 16;
  h *= 0x85ebca6b;
  h ^= h >> 13;
  h *= 0xc2b2ae35;
  h ^= h >> 16;

  return h;
}

void rhp_murmur_hash3_x86_32 (const void * key, int len,u_int32_t seed, void * out)
{
  const u_int8_t * data = (const u_int8_t*)key;
  const int nblocks = len / 4;
  int i;

  u_int32_t h1 = seed;

  u_int32_t c1 = 0xcc9e2d51;
  u_int32_t c2 = 0x1b873593;

  //----------
  // body

  const u_int32_t * blocks = (const u_int32_t *)(data + nblocks*4);

  for(i = -nblocks; i; i++){

  	u_int32_t k1 = _rhp_murmur_hash3_getblock(blocks,i);

    k1 *= c1;
    k1 = RHP_MURMUR_HASH3_ROTL32(k1,15);
    k1 *= c2;

    h1 ^= k1;
    h1 = RHP_MURMUR_HASH3_ROTL32(h1,13);
    h1 = h1*5+0xe6546b64;
  }

  //----------
  // tail

  const u_int8_t * tail = (const u_int8_t*)(data + nblocks*4);

  u_int32_t k1 = 0;

  switch(len & 3)
  {
  case 3: k1 ^= tail[2] << 16;
  case 2: k1 ^= tail[1] << 8;
  case 1: k1 ^= tail[0];
          k1 *= c1; k1 = RHP_MURMUR_HASH3_ROTL32(k1,15); k1 *= c2; h1 ^= k1;
  };

  //----------
  // finalization

  h1 ^= len;

  h1 = _rhp_murmur_hash3_fmix(h1);

  *(u_int32_t*)out = h1;
}

//-----------------------------------------------------------------------------





static int _rhp_bloom_filter_fread(int fd,int buf_len,u8* buf,off_t offset)
{
	int err = -EINVAL;
	ssize_t n = 0, n2 = 0;
	u8* p = buf;

	if( lseek(fd,offset,SEEK_SET) < 0 ){
		err = -errno;
		goto error;
	}

	while( 1 ){

		n = read(fd,p,(buf_len - n2));
		if( n < 0 ){

			err = -errno;
			goto error;

		}else if( n == 0 ){
			break;
		}

		n2 += n;
		if( n2 >= buf_len ){
			break;
		}

		p += n;
	}

	if( n2 != buf_len ){
		err = -EMSGSIZE;
		goto error;
	}

	return 0;

error:
	printf("_rhp_bloom_filter_fread error: %s\n",strerror(-err));
	return err;
}

static int _rhp_bloom_filter_fwrite(int fd,int buf_len,u8* buf,off_t offset)
{
	int err = -EINVAL;
	u8* fpt = buf;
	int n = buf_len;

	if( lseek(fd,offset,SEEK_SET) < 0 ){
		err = -errno;
		goto error;
	}

	while( n > 0 ){

		int c = write(fd,fpt,n);
		if( c < 0 ){
			err = -errno;
			goto error;
		}

		n -= c;
		fpt += c;
	}

	return 0;

error:
	printf("_rhp_bloom_filter_fwrite error: %s\n",strerror(-err));
	return err;
}

static int _rhp_bloom_filter_fsync(int fd)
{
	if( fdatasync(fd) < 0 ){
		return -errno;
	}

	return 0;
}

static int _rhp_bloom_filter_update_file(rhp_bloom_filter* bf_ctx)
{
	int err;
	int ext_len;

	if( bf_ctx->fd <= 0 ){
		return 0;
	}

	ext_len = sizeof(rhp_bloom_filter_fdata) + bf_ctx->bitmap_bytes_len
						+ (sizeof(32)*bf_ctx->hashes_num);

	bf_ctx->fdata->added_num = bf_ctx->added_num;
	bf_ctx->fdata->collision_num = bf_ctx->collision_num;
	memcpy((u8*)(bf_ctx->fdata + 1),bf_ctx->bitmap,bf_ctx->bitmap_bytes_len);

	err = _rhp_bloom_filter_fwrite(bf_ctx->fd,ext_len,(u8*)(bf_ctx->fdata),0);
	if( err ){
		goto error;
	}
	_rhp_bloom_filter_fsync(bf_ctx->fd);

	return 0;

error:
	printf("_rhp_bloom_filter_update_file error: %s\n",strerror(-err));
	return err;
}

static int _rhp_bloom_filter_update_file_bitmap(rhp_bloom_filter* bf_ctx,
		int bitmap_blk_idxes_num)
{
	int err, i;

	if( bf_ctx->fd <= 0 ){
		return 0;
	}

	for( i = 0; i < bitmap_blk_idxes_num; i++){

		int idx = bf_ctx->bitmap_updated_idxes[i];

		if( idx < bf_ctx->bitmap_bytes_len ){

			((u8*)(bf_ctx->fdata + 1))[idx] = bf_ctx->bitmap[idx];
		}
	}

	for( i = 0; i < bitmap_blk_idxes_num; i++){

		int idx = bf_ctx->bitmap_updated_idxes[i];
		off_t offset = sizeof(rhp_bloom_filter_fdata) + sizeof(u8)*idx;

		if( idx < bf_ctx->bitmap_bytes_len ){

			err = _rhp_bloom_filter_fwrite(bf_ctx->fd,sizeof(u8),bf_ctx->bitmap + idx,offset);
			if( err ){
				goto error;
			}
		}
	}

	return 0;

error:
	printf("_rhp_bloom_filter_update_file_bitmap error: %s\n",strerror(-err));
	return err;
}

static int _rhp_bloom_filter_update_file_header(rhp_bloom_filter* bf_ctx)
{
	int err;

	if( bf_ctx->fd <= 0 ){
		return 0;
	}

	bf_ctx->fdata->added_num = bf_ctx->added_num;
	bf_ctx->fdata->collision_num = bf_ctx->collision_num;

	err = _rhp_bloom_filter_fwrite(bf_ctx->fd,
					sizeof(rhp_bloom_filter_fdata),(u8*)(bf_ctx->fdata),0);
	if( err ){
		goto error;
	}

	return 0;

error:
	printf("_rhp_bloom_filter_update_file_header error: %s\n",strerror(-err));
	return err;
}


static int _rhp_bloom_filter_add_impl(rhp_bloom_filter* bf_ctx,
		size_t element_len,u8* element,int check_only)
{
	int i, ret = 0;
	u32 found = 0;
	int updated_blk_num = 0;

	for( i = 0; i < bf_ctx->hashes_num; i++ ){

		u32 hval, n;
		u8 bm;

		rhp_murmur_hash3_x86_32((void*)element,element_len,bf_ctx->salts[i],(void*)&hval);

		hval = hval % bf_ctx->bitmap_len;

		n = hval >> 3;
		bm = (1 << (hval % 8));

		if( bf_ctx->bitmap[n] & bm ){

			found++;

		}else{

			if( !check_only ){

				bf_ctx->bitmap[n] |= bm;

				if( bf_ctx->bitmap_updated_idxes ){

					bf_ctx->bitmap_updated_idxes[updated_blk_num] = n;
					updated_blk_num++;
				}
			}
		}
	}

	if( found == bf_ctx->hashes_num ){

		if( !check_only ){
			bf_ctx->collision_num++;
		}

		ret = 1;

	}else{

		if( !check_only ){
			bf_ctx->added_num++;
		}
	}

	if( !check_only && bf_ctx->fd > -1 ){

		_rhp_bloom_filter_update_file_header(bf_ctx);

		if( updated_blk_num ){

			_rhp_bloom_filter_update_file_bitmap(bf_ctx,updated_blk_num);
		}

		_rhp_bloom_filter_fsync(bf_ctx->fd);
	}

	return ret;
}

static int _rhp_bloom_filter_add(rhp_bloom_filter* bf_ctx,
		size_t element_len,u8* element)
{
	int ret;

	pthread_mutex_lock(&(bf_ctx->lock));

	ret = _rhp_bloom_filter_add_impl(bf_ctx,element_len,element,0);

	pthread_mutex_unlock(&(bf_ctx->lock));

	return ret;
}

static int _rhp_bloom_filter_contains(rhp_bloom_filter* bf_ctx,
		size_t element_len,u8* element)
{
	int ret;

	pthread_mutex_lock(&(bf_ctx->lock));

	ret =_rhp_bloom_filter_add_impl(bf_ctx,element_len,element,1);

	pthread_mutex_unlock(&(bf_ctx->lock));

	return ret;
}

static void _rhp_bloom_filter_reset(rhp_bloom_filter* bf_ctx)
{
	pthread_mutex_lock(&(bf_ctx->lock));

	bf_ctx->added_num = 0;
	bf_ctx->collision_num = 0;
	memset(bf_ctx->bitmap,0,sizeof(u8)*bf_ctx->bitmap_bytes_len);

	if( bf_ctx->fd > -1 ){

		_rhp_bloom_filter_update_file(bf_ctx);
	}

 	pthread_mutex_unlock(&(bf_ctx->lock));
	return;
}

static u32 _rhp_bloom_filter_get_num(rhp_bloom_filter* bf_ctx)
{
	u32 ret;

	pthread_mutex_lock(&(bf_ctx->lock));

	ret = bf_ctx->added_num;

 	pthread_mutex_unlock(&(bf_ctx->lock));

 	return ret;
}

static u32 _rhp_bloom_filter_get_collision_num(rhp_bloom_filter* bf_ctx)
{
	u32 ret;

	pthread_mutex_lock(&(bf_ctx->lock));

	ret = bf_ctx->collision_num;

 	pthread_mutex_unlock(&(bf_ctx->lock));

 	return ret;
}

static u8* _rhp_bloom_filter_get_tag(rhp_bloom_filter* bf_ctx)
{
	if( bf_ctx->fdata ){
	 	return bf_ctx->fdata->tag;
	}
	return NULL;
}

static inline void _rhp_bloom_filter_print_dump(char* d,int len)
{
  int i,j;
  char* mc = d;
  printf("addr : 0x%lx , len : %d\n",(unsigned long)d,len);
  printf("*0 *1 *2 *3 *4 *5 *6 *7 *8 *9 *A *B *C *D *E *F     0123456789ABCDEF\n");
  for( i = 0;i < len; i++ ){
    int pd;
    if( i && (i % 16) == 0 ){
      printf("    ");
      for( j = 0;j < 16; j++ ){
        if( *mc >= 33 && *mc <= 126 ){printf("%c",*mc);
        }else{printf(".");}
        mc++;
      }
      printf("\n");
    }

    pd = ((*(int *)d) & 0x000000FF);

    if( pd <= 0x0F ){printf("0");}
    printf("%x ",pd);
    d++;
  }

  {
    int k,k2;
    if( (i % 16) == 0 ){
      k = 0;
      k2 = 16;
    }else{
      k = 16 - (i % 16);
      k2 = (i % 16);
    }
    for( i = 0; i < k;i++ ){printf("   ");}
    printf("    ");
    for( j = 0;j < k2; j++ ){
      if( *mc >= 33 && *mc <= 126 ){
        printf("%c",*mc);
      }else{printf(".");
      }
      mc++;
    }
  }

  printf("\n");
}

static void _rhp_bloom_filter_dump_def(rhp_bloom_filter* bf_ctx)
{
	if( bf_ctx ){

		int i;

	 	pthread_mutex_lock(&(bf_ctx->lock));

		printf("bf_ctx->max_num_of_elements: %u\n", bf_ctx->max_num_of_elements);
		printf("bf_ctx->false_ratio: %f\n", bf_ctx->false_ratio);
		printf("bf_ctx->hashes_num: %u\n", bf_ctx->hashes_num);
		printf("bf_ctx->bitmap_len: %u\n", bf_ctx->bitmap_len);
		printf("bf_ctx->bitmap_bytes_len: %u\n", bf_ctx->bitmap_bytes_len);

		printf("bf_ctx->bitmap: \n");
		_rhp_bloom_filter_print_dump((char*)bf_ctx->bitmap,bf_ctx->bitmap_bytes_len);
		printf("\n");

		for( i = 0; i < bf_ctx->hashes_num; i++){
			printf("bf_ctx->salt[%d]: %u\n",i,*(bf_ctx->salts + i));
		}


		printf("\n");
		printf("bf_ctx->added_num: %u\n", bf_ctx->added_num);
		printf("bf_ctx->collision_num: %u\n", bf_ctx->collision_num);

		if( bf_ctx->file_path ){

			int ext_len = sizeof(rhp_bloom_filter_fdata)
										+ bf_ctx->bitmap_bytes_len + (sizeof(32)*bf_ctx->hashes_num);

			printf("\n");
			printf("bf_ctx->file_path: %s\n", bf_ctx->file_path);
			printf("bf_ctx->fd: %d\n", bf_ctx->fd);

			printf("bf_ctx->fdata->magic: 0x%x\n",bf_ctx->fdata->magic);
			printf("bf_ctx->fdata->max_num_of_elements: %u\n",bf_ctx->fdata->max_num_of_elements);
			printf("bf_ctx->fdata->false_ratio: %f\n",bf_ctx->fdata->false_ratio);
			printf("bf_ctx->fdata->added_num: %u\n",bf_ctx->fdata->added_num);
			printf("bf_ctx->fdata->collision_num: %u\n",bf_ctx->fdata->collision_num);
			printf("bf_ctx->fdata: \n");
			_rhp_bloom_filter_print_dump((char*)bf_ctx->fdata,ext_len);
			printf("\n");


			for( i = 0; i < bf_ctx->hashes_num; i++){
				printf("bf_ctx->bitmap_updated_idxes[%d]: %lu\n",i,*(bf_ctx->bitmap_updated_idxes + i));
			}
		}

	 	pthread_mutex_unlock(&(bf_ctx->lock));

	}else{

		printf("bf_ctx == NULL\n");
	}
}


static void _rhp_bloom_filter_free_impl(rhp_bloom_filter* bf_ctx,void (*mfree_cb)(void *ptr))
{
	if( bf_ctx ){

		if( bf_ctx->bitmap ){
			(mfree_cb ? mfree_cb : _rhp_free_def)(bf_ctx->bitmap);
		}

		if( bf_ctx->salts ){
			(mfree_cb ? mfree_cb : _rhp_free_def)(bf_ctx->salts);
		}

		if( bf_ctx->file_path ){
			(mfree_cb ? mfree_cb : _rhp_free_def)(bf_ctx->file_path);
		}

		if( bf_ctx->fdata ){
			(mfree_cb ? mfree_cb : _rhp_free_def)(bf_ctx->fdata);
		}

		if( bf_ctx->bitmap_updated_idxes ){
			(mfree_cb ? mfree_cb : _rhp_free_def)(bf_ctx->bitmap_updated_idxes);
		}

		if( bf_ctx->fd > -1 ){
			close(bf_ctx->fd);
		}

		pthread_mutex_destroy(&(bf_ctx->lock));

		(mfree_cb ? mfree_cb : _rhp_free_def)(bf_ctx);
	}
}

void rhp_bloom_filter_free(rhp_bloom_filter* bf_ctx)
{
	_rhp_bloom_filter_free_impl(bf_ctx,bf_ctx->mfree);
}


rhp_bloom_filter* rhp_bloom_filter_alloc_ex(
		u64 max_num_of_elements,double false_ratio,
		const char* file_path,
		mode_t file_mode,
		void (*dump_cb)(struct _rhp_bloom_filter* bf_ctx),
		void* (*malloc_cb)(size_t size),
		void (*mfree_cb)(void *ptr),
		int (*random_bytes_cb)(u8* buf,size_t buf_len),
		u8* tag)
{
	rhp_bloom_filter* bf_ctx = NULL;
	double ln_p, n;
	double ln_2 = 0.693147180559945;
	double ln_2_sqr = 0.480453013918201;
	size_t file_path_len = 0, salts_len = 0;
	int i, err = 0, ext_len = 0;
	rhp_bloom_filter_fdata bf_fdata;

	memset(&bf_fdata,0,sizeof(rhp_bloom_filter_fdata));

	bf_ctx = (rhp_bloom_filter*)(malloc_cb ? malloc_cb : _rhp_malloc_def)(sizeof(rhp_bloom_filter));
	if(bf_ctx == NULL){
		return NULL;
	}

	memset(bf_ctx,0,sizeof(rhp_bloom_filter));

	bf_ctx->tag[0] = '#';
	bf_ctx->tag[1] = 'B';
	bf_ctx->tag[2] = 'L';
	bf_ctx->tag[3] = 'F';

	bf_ctx->max_num_of_elements = max_num_of_elements;
	bf_ctx->false_ratio = false_ratio;
	bf_ctx->fd = -1;


	if( file_path ){

		file_path_len = strlen(file_path) + 1;
		bf_ctx->file_path = (char*)(malloc_cb ? malloc_cb : _rhp_malloc_def)(file_path_len);
		if( bf_ctx->file_path == NULL ){
			goto error;
		}
		bf_ctx->file_path[0] = '\0';
		strcpy(bf_ctx->file_path,file_path);

		bf_ctx->fd = open(file_path,O_RDWR);
		if( bf_ctx->fd < 0 ){

			err = -errno;

			if( err != -ENOENT ){
				goto error;
			}

		}else{

			err = _rhp_bloom_filter_fread(bf_ctx->fd,
							sizeof(rhp_bloom_filter_fdata),(u8*)&bf_fdata,0);
			if( err ){
				goto error;
			}

			if( bf_fdata.magic != RHP_BFLTR_FDATA_MAGIC ){
				goto error;
			}

			false_ratio = bf_fdata.false_ratio;
			max_num_of_elements = bf_fdata.max_num_of_elements;

			bf_ctx->added_num = bf_fdata.added_num;
			bf_ctx->collision_num = bf_fdata.collision_num;
		}
	}


	if( max_num_of_elements == 0 ){
		goto error;
	}

	if( false_ratio == 0 ){
		goto error;
	}


	ln_p = log(false_ratio);
	n = -(ln_p/ln_2_sqr);

	bf_ctx->bitmap_len = (u32)ceil(((double)max_num_of_elements) * n);
	bf_ctx->bitmap_bytes_len = bf_ctx->bitmap_len >> 3;
	if( bf_ctx->bitmap_len % 8 ){
		bf_ctx->bitmap_bytes_len++;
	}


	bf_ctx->hashes_num = (u32)ceil(n * ln_2);


	bf_ctx->bitmap = (u8*)(malloc_cb ? malloc_cb : _rhp_malloc_def)(bf_ctx->bitmap_bytes_len);
	if( bf_ctx->bitmap == NULL ){
		goto error;
	}
	memset(bf_ctx->bitmap,0,bf_ctx->bitmap_bytes_len);

	salts_len = sizeof(32)*bf_ctx->hashes_num;
	bf_ctx->salts = (u32*)(malloc_cb ? malloc_cb : _rhp_malloc_def)(salts_len);
	if( bf_ctx->salts == NULL ){
		goto error;
	}

	if( file_path == NULL ||
			bf_fdata.magic != RHP_BFLTR_FDATA_MAGIC ){

		for( i = 0; i < bf_ctx->hashes_num; i++){

			if( (random_bytes_cb ? random_bytes_cb : _rhp_random_bytes_def)((u8*)(bf_ctx->salts + i),
					sizeof(u32)) ){
				goto error;
			}
		}
	}


	if( file_path ){

		int bm_idxes_len = sizeof(unsigned long)*bf_ctx->hashes_num;

		bf_ctx->bitmap_updated_idxes
			= (unsigned long*)(malloc_cb ? malloc_cb : _rhp_malloc_def)(bm_idxes_len);
		if( bf_ctx->bitmap_updated_idxes == NULL ){
			goto error;
		}
		memset(bf_ctx->bitmap_updated_idxes,0,bm_idxes_len);


		ext_len = sizeof(rhp_bloom_filter_fdata) + bf_ctx->bitmap_bytes_len + salts_len;

		bf_ctx->fdata = (rhp_bloom_filter_fdata*)(malloc_cb ? malloc_cb : _rhp_malloc_def)(ext_len);
		if( bf_ctx->fdata == NULL ){
			goto error;
		}

		if( bf_fdata.magic == RHP_BFLTR_FDATA_MAGIC ){

			memcpy(bf_ctx->fdata,&bf_fdata,sizeof(rhp_bloom_filter_fdata));

			err = _rhp_bloom_filter_fread(bf_ctx->fd,
							(ext_len - sizeof(rhp_bloom_filter_fdata)),(u8*)(bf_ctx->fdata + 1),
							sizeof(rhp_bloom_filter_fdata));
			if( err ){
				goto error;
			}

			memcpy(bf_ctx->bitmap,(u8*)(bf_ctx->fdata + 1),bf_ctx->bitmap_bytes_len);
			memcpy(bf_ctx->salts,((u8*)(bf_ctx->fdata + 1)) + bf_ctx->bitmap_bytes_len,salts_len);

		}else{

			memset(bf_ctx->fdata,0,ext_len);

			bf_ctx->fdata->magic = RHP_BFLTR_FDATA_MAGIC;
			bf_ctx->fdata->max_num_of_elements = max_num_of_elements;
			bf_ctx->fdata->false_ratio = false_ratio;

			if( tag ){
				memcpy(bf_ctx->fdata->tag,tag,RHP_BFLTR_FDATA_TAG_LEN);
			}

			memcpy(((u8*)(bf_ctx->fdata + 1)) + bf_ctx->bitmap_bytes_len,bf_ctx->salts,salts_len);

			bf_ctx->fd = open(file_path,(O_RDWR | O_CREAT),file_mode);
			if( bf_ctx->fd < 0 ){
				goto error;
			}

			err = _rhp_bloom_filter_fwrite(bf_ctx->fd,ext_len,(u8*)(bf_ctx->fdata),0);
			if( err ){
				goto error;
			}
			_rhp_bloom_filter_fsync(bf_ctx->fd);
		}
	}


	if( pthread_mutex_init(&(bf_ctx->lock),NULL) ){
		goto error;
	}


	bf_ctx->add = _rhp_bloom_filter_add;
	bf_ctx->contains = _rhp_bloom_filter_contains;
	bf_ctx->reset = _rhp_bloom_filter_reset;
	bf_ctx->get_num = _rhp_bloom_filter_get_num;
	bf_ctx->get_collision_num = _rhp_bloom_filter_get_collision_num;
	bf_ctx->get_tag = _rhp_bloom_filter_get_tag;


	bf_ctx->dump = (dump_cb ? dump_cb : _rhp_bloom_filter_dump_def);
	bf_ctx->malloc = (malloc_cb ? malloc_cb : _rhp_malloc_def);
	bf_ctx->mfree = (mfree_cb ? mfree_cb : _rhp_free_def);
	bf_ctx->random_bytes = (random_bytes_cb ? random_bytes_cb : _rhp_random_bytes_def);

	return bf_ctx;

error:
	_rhp_bloom_filter_free_impl(bf_ctx,(mfree_cb ? mfree_cb : _rhp_free_def));
	return NULL;
}

rhp_bloom_filter* rhp_bloom_filter_alloc(u64 max_num_of_elements,double false_ratio)
{
	return rhp_bloom_filter_alloc_ex(max_num_of_elements,false_ratio,NULL,0,NULL,NULL,NULL,NULL,NULL);
}

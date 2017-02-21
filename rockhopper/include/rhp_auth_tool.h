/*

	Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.
	
	You can redistribute and/or modify this software under the 
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/


#ifndef _RHP_AUTH_TOOL_H_
#define _RHP_AUTH_TOOL_H_

struct _rhp_crypto_prf; // Only HMAC-SHA-1 is supported.

#define RHP_AUTH_PASSWORD_KEYPAD  "HIRAKE, GOMA (OPEN, SESAME):"

static inline int _rhp_auth_hashed_auth_key(struct _rhp_crypto_prf* prf,unsigned char* id,unsigned long id_len,
		unsigned char* password,unsigned long password_len,u8** hashed_key_r,int* hashed_key_len_r)
{
  int err = -EINVAL;
  unsigned char* hashed_key = NULL;
  int hashed_key_len = 0;
  int password_pad_len = 0;
  unsigned char* password_pad = NULL;
  int keypad_len = strlen(RHP_AUTH_PASSWORD_KEYPAD);
	
  if( password_len <= 1 ){
    goto error;
  }
  
    
  if( (err = prf->set_key(prf,password,password_len)) ){
    RHP_BUG("");
    goto error;
  }

  password_pad_len = keypad_len + (id_len-1);
  password_pad = _rhp_malloc(password_pad_len);
  if( password_pad == NULL ){
    RHP_BUG("");
    err = -ENOMEM;
    goto error;
  }
  memset(password_pad,0,password_pad_len);

  memcpy(password_pad,RHP_AUTH_PASSWORD_KEYPAD,keypad_len);
  memcpy((password_pad + keypad_len),id,(id_len-1));

  hashed_key_len = prf->get_output_len(prf);

  hashed_key = (unsigned char*)_rhp_malloc(hashed_key_len);
  if( hashed_key == NULL ){
    RHP_BUG("");
    err = -ENOMEM;
    goto error;
  }
  
  if( (err = prf->compute(prf,
       (unsigned char*)password_pad,password_pad_len,hashed_key,hashed_key_len)) ){
    RHP_BUG("%d",err);
    goto error;
  }
  
  if( password_pad ){
    _rhp_free_zero(password_pad,password_pad_len);
  }
  

  *hashed_key_r = hashed_key;
  *hashed_key_len_r = hashed_key_len;

  return 0;
  
error:
  if( hashed_key ){
    _rhp_free_zero(hashed_key,hashed_key_len);
  }
  if( password_pad ){
    _rhp_free_zero(password_pad,password_pad_len);
  }
  return err;
}

#endif // _RHP_AUTH_TOOL_H_


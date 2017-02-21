/*

	Copyright (C) 2015-2016 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.

	You can redistribute and/or modify this software under the
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/

#ifndef _RHP_RADIUS_ACCT_H_
#define _RHP_RADIUS_ACCT_H_


/*
 *
 * - See rhp_radius_acct.c and rhp_main.c for the following
 *   funcitons.
 *
 *   extern int rhp_radius_acct_init();
 *
 *   extern int rhp_radius_acct_cleanup();
 *
*/


// status: RHP_RADIUS_ATTR_TYPE_ACCT_STATUS_XXX
// term_cause: RHP_RADIUS_ATTR_TYPE_ACCT_TERM_CAUSE_XXX
extern int rhp_radius_acct_send(rhp_vpn* vpn,int status,int term_cause);


extern char* rhp_radius_acct_get_session_id_str(rhp_vpn* vpn);

#endif // _RHP_RADIUS_ACCT_H_

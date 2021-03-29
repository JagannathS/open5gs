/*
 * Copyright (C) 2019 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "ogs-diameter-cx.h"

#include "test-common.h"
#include "pcscf-fd-path.h"

static struct disp_hdl *hdl_cx_fb = NULL; 
static struct disp_hdl *hdl_cx_uaa = NULL; 

static int pcscf_cx_fb_cb(struct msg **msg, struct avp *avp, 
        struct session *sess, void *opaque, enum disp_action *act)
{
	/* This CB should never be called */
	ogs_warn("Unexpected message received!");
	
	return ENOTSUP;
}

/* Callback for incoming User-Authorization-Answer messages */
static int pcscf_cx_uaa_cb( struct msg **msg, struct avp *avp, 
        struct session *session, void *opaque, enum disp_action *act)
{
    return 0;
}

int pcscf_cx_init(void)
{
    int ret;
	struct disp_when data;

	/* Install objects definitions for this application */
	ret = ogs_diam_cx_init();
    ogs_assert(ret == 0);

	/* Fallback CB if command != unexpected message received */
	memset(&data, 0, sizeof(data));
	data.app = ogs_diam_cx_application;

	ret = fd_disp_register(pcscf_cx_fb_cb, DISP_HOW_APPID, &data, NULL,
                &hdl_cx_fb);
    ogs_assert(ret == 0);
	
	/* Specific handler for User-Authorization-Answer */
	data.command = ogs_diam_cx_cmd_uaa;
	ret = fd_disp_register(pcscf_cx_uaa_cb, DISP_HOW_CC, &data, NULL,
                &hdl_cx_uaa);
    ogs_assert(ret == 0);

	/* Advertise the support for the application in the peer */
	ret = fd_disp_app_support(ogs_diam_cx_application, ogs_diam_vendor, 1, 0);
    ogs_assert(ret == 0);

	return 0;
}

void pcscf_cx_final(void)
{
	if (hdl_cx_fb)
		(void) fd_disp_unregister(&hdl_cx_fb, NULL);
	if (hdl_cx_uaa)
		(void) fd_disp_unregister(&hdl_cx_uaa, NULL);
}

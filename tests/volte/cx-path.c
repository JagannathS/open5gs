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

static struct session_handler *test_cx_reg = NULL;

struct sess_state {
    test_ue_t *test_ue;
    struct timespec ts; /* Time of sending the message */
};

static struct disp_hdl *hdl_cx_fb = NULL; 
static struct disp_hdl *hdl_cx_uaa = NULL; 

static void test_cx_uaa_cb(void *data, struct msg **msg);

static void state_cleanup(struct sess_state *sess_data, os0_t sid, void *opaque)
{
    ogs_free(sess_data);
}

static int test_cx_fb_cb(struct msg **msg, struct avp *avp,
        struct session *sess, void *opaque, enum disp_action *act)
{
	/* This CB should never be called */
	ogs_warn("Unexpected message received!");
	
	return ENOTSUP;
}

void icscf_cx_send_uar(test_ue_t *test_ue, int id_type)
{
    int ret;

    struct msg *req = NULL;

    struct msg_hdr *msg_header = NULL;

    struct session *session = NULL;
    struct sess_state *sess_data = NULL, *svg;

    struct avp *avp = NULL;
    union avp_value val;

    ogs_assert(test_ue);

    ogs_debug("User-Authroization-Request");

    /* Create the random value to store with the session */
    sess_data = ogs_calloc(1, sizeof (*sess_data));
    ogs_assert(sess_data);

    sess_data->test_ue = test_ue;

    /* Create the request */
    ret = fd_msg_new(ogs_diam_cx_cmd_uar, MSGFL_ALLOC_ETEID, &req);
    ogs_assert(ret == 0);

    ret = fd_msg_hdr(req, &msg_header);
    ogs_assert(ret == 0);
    msg_header->msg_appl = OGS_DIAM_CX_APPLICATION_ID;

    #define OGS_DIAM_CX_APP_SID_OPT  "app_cx"
    ret = fd_msg_new_session(req, (os0_t)OGS_DIAM_CX_APP_SID_OPT,
            CONSTSTRLEN(OGS_DIAM_CX_APP_SID_OPT));
    ogs_assert(ret == 0);
    ret = fd_msg_sess_get(fd_g_config->cnf_dict, req, &session, NULL);
    ogs_assert(ret == 0);

    /* Set Vendor-Specific-Application-Id AVP */
    ret = ogs_diam_message_vendor_specific_appid_set(
            req, OGS_DIAM_CX_APPLICATION_ID);
    ogs_assert(ret == 0);

    /* Set the Auth-Session-State AVP */
    ret = fd_msg_avp_new(ogs_diam_auth_session_state, 0, &avp);
    ogs_assert(ret == 0);
    val.i32 = 1;
    ret = fd_msg_avp_setvalue(avp, &val);
    ogs_assert(ret == 0);
    ret = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
    ogs_assert(ret == 0);

    /* Set Origin-Host & Origin-Realm */
    ret = fd_msg_add_origin(req, 0);
    ogs_assert(ret == 0);

    /* Set the Destination-Host AVP */
    ret = fd_msg_avp_new(ogs_diam_destination_host, 0, &avp);
    ogs_assert(ret == 0);
    val.os.data = TEST_HSS_IDENTITY;
    val.os.len  = strlen(TEST_HSS_IDENTITY);
    ret = fd_msg_avp_setvalue(avp, &val);
    ogs_assert(ret == 0);
    ret = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
    ogs_assert(ret == 0);

    /* Set the Destination-Realm AVP */
    ret = fd_msg_avp_new(ogs_diam_destination_realm, 0, &avp);
    ogs_assert(ret == 0);
    val.os.data = (unsigned char *)(fd_g_config->cnf_diamrlm);
    val.os.len  = strlen(fd_g_config->cnf_diamrlm);
    ret = fd_msg_avp_setvalue(avp, &val);
    ogs_assert(ret == 0);
    ret = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
    ogs_assert(ret == 0);

    /* Set the User-Name AVP */
    ret = fd_msg_avp_new(ogs_diam_user_name, 0, &avp);
    ogs_assert(ret == 0);
    val.os.data = (uint8_t *)test_ue->imsi;
    val.os.len = strlen(test_ue->imsi);
    ret = fd_msg_avp_setvalue(avp, &val);
    ogs_assert(ret == 0);
    ret = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
    ogs_assert(ret == 0);

    /* Set the Public-Identity AVP */
    ret = fd_msg_avp_new(ogs_diam_cx_public_identity, 0, &avp);
    ogs_assert(ret == 0);
    val.os.data = (uint8_t *)test_ue->imsi;
    val.os.len = strlen(test_ue->imsi);
    ret = fd_msg_avp_setvalue(avp, &val);
    ogs_assert(ret == 0);
    ret = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
    ogs_assert(ret == 0);

    /* Set the Visited-Network-Identifier AVP */
    ret = fd_msg_avp_new(ogs_diam_cx_visited_network_identifier, 0, &avp);
    ogs_assert(ret == 0);
    val.os.data = (unsigned char *)(fd_g_config->cnf_diamrlm);
    val.os.len  = strlen(fd_g_config->cnf_diamrlm);
    ret = fd_msg_avp_setvalue(avp, &val);
    ogs_assert(ret == 0);
    ret = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
    ogs_assert(ret == 0);

    ret = clock_gettime(CLOCK_REALTIME, &sess_data->ts);
    ogs_assert(ret == 0);

    /* Keep a pointer to the session data for debug purpose,
     * in real life we would not need it */
    svg = sess_data;

    /* Store this value in the session */
    ret = fd_sess_state_store(test_cx_reg, session, &sess_data);
    ogs_assert(ret == 0);
    ogs_assert(sess_data == 0);

    /* Send the request */
    ret = fd_msg_send(&req, test_cx_uaa_cb, svg);
    ogs_assert(ret == 0);

    /* Increment the counter */
    ogs_assert(pthread_mutex_lock(&ogs_diam_logger_self()->stats_lock) == 0);
    ogs_diam_logger_self()->stats.nb_sent++;
    ogs_assert(pthread_mutex_unlock(&ogs_diam_logger_self()->stats_lock) == 0);
}

/* Callback for incoming User-Authorization-Answer messages */
static void test_cx_uaa_cb(void *data, struct msg **msg)
{
    int ret, new;

    unsigned long dur;
    int error = 0;

    struct sess_state *sess_data = NULL;
    struct timespec ts;
    struct session *session;

    test_ue_t *test_ue = NULL;

    ogs_debug("User-Authroization-Answer");

    ret = clock_gettime(CLOCK_REALTIME, &ts);
    ogs_assert(ret == 0);

    /* Search the session, retrieve its data */
    ret = fd_msg_sess_get(fd_g_config->cnf_dict, *msg, &session, &new);
    ogs_expect_or_return(ret == 0);
    ogs_expect_or_return(new == 0);

    ret = fd_sess_state_retrieve(test_cx_reg, session, &sess_data);
    ogs_expect_or_return(ret == 0);
    ogs_expect_or_return(sess_data);
    ogs_expect_or_return((void *)sess_data == data);

    test_ue = sess_data->test_ue;
    ogs_assert(test_ue);

    /* Free the message */
    ogs_assert(pthread_mutex_lock(&ogs_diam_logger_self()->stats_lock) == 0);
    dur = ((ts.tv_sec - sess_data->ts.tv_sec) * 1000000) +
        ((ts.tv_nsec - sess_data->ts.tv_nsec) / 1000);
    if (ogs_diam_logger_self()->stats.nb_recv) {
        /* Ponderate in the avg */
        ogs_diam_logger_self()->stats.avg = (ogs_diam_logger_self()->stats.avg *
            ogs_diam_logger_self()->stats.nb_recv + dur) /
            (ogs_diam_logger_self()->stats.nb_recv + 1);
        /* Min, max */
        if (dur < ogs_diam_logger_self()->stats.shortest)
            ogs_diam_logger_self()->stats.shortest = dur;
        if (dur > ogs_diam_logger_self()->stats.longest)
            ogs_diam_logger_self()->stats.longest = dur;
    } else {
        ogs_diam_logger_self()->stats.shortest = dur;
        ogs_diam_logger_self()->stats.longest = dur;
        ogs_diam_logger_self()->stats.avg = dur;
    }
    if (error)
        ogs_diam_logger_self()->stats.nb_errs++;
    else
        ogs_diam_logger_self()->stats.nb_recv++;

    ogs_assert(pthread_mutex_unlock(&ogs_diam_logger_self()->stats_lock) == 0);

    /* Display how long it took */
    if (ts.tv_nsec > sess_data->ts.tv_nsec)
        ogs_trace("in %d.%06ld sec",
                (int)(ts.tv_sec - sess_data->ts.tv_sec),
                (long)(ts.tv_nsec - sess_data->ts.tv_nsec) / 1000);
    else
        ogs_trace("in %d.%06ld sec",
                (int)(ts.tv_sec + 1 - sess_data->ts.tv_sec),
                (long)(1000000000 + ts.tv_nsec - sess_data->ts.tv_nsec) / 1000);

    ret = fd_msg_free(*msg);
    ogs_assert(ret == 0);
    *msg = NULL;

    state_cleanup(sess_data, NULL, NULL);
    return;
}

int test_cx_init(void)
{
    int ret;
	struct disp_when data;

	/* Install objects definitions for this application */
	ret = ogs_diam_cx_init();
    ogs_assert(ret == 0);

    /* Create handler for sessions */
	ret = fd_sess_handler_create(&test_cx_reg, &state_cleanup, NULL, NULL);
    ogs_assert(ret == 0);

	/* Fallback CB if command != unexpected message received */
	memset(&data, 0, sizeof(data));
	data.app = ogs_diam_cx_application;

	ret = fd_disp_register(test_cx_fb_cb, DISP_HOW_APPID, &data, NULL,
                &hdl_cx_fb);
    ogs_assert(ret == 0);
	
	/* Advertise the support for the application in the peer */
	ret = fd_disp_app_support(ogs_diam_cx_application, ogs_diam_vendor, 1, 0);
    ogs_assert(ret == 0);

	return 0;
}

void test_cx_final(void)
{
    int ret;

	ret = fd_sess_handler_destroy(&test_cx_reg, NULL);
    ogs_assert(ret == OGS_OK);

	if (hdl_cx_fb)
		(void) fd_disp_unregister(&hdl_cx_fb, NULL);
	if (hdl_cx_uaa)
		(void) fd_disp_unregister(&hdl_cx_uaa, NULL);
}

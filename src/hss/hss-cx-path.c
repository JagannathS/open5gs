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

#include "ogs-crypt.h"

#include "hss-context.h"
#include "hss-fd-path.h"

/* handler for fallback cb */
static struct disp_hdl *hdl_cx_fb = NULL; 
/* handler for Authentication-Information-Request cb */
static struct disp_hdl *hdl_cx_uar = NULL; 

/* Default callback for the application. */
static int hss_ogs_diam_cx_fb_cb(struct msg **msg, struct avp *avp, 
        struct session *session, void *opaque, enum disp_action *act)
{
	/* This CB should never be called */
	ogs_warn("Unexpected message received!");
	
	return ENOTSUP;
}

/* Callback for incoming Authentication-Information-Request messages */
static int hss_ogs_diam_cx_uar_cb( struct msg **msg, struct avp *avp, 
        struct session *session, void *opaque, enum disp_action *act)
{
    int ret;

	struct msg *ans, *qry;

    struct avp_hdr *hdr;
    union avp_value val;
#if 0
    struct avp *avpch;
    struct avp *avp_e_utran_vector, *avp_xres, *avp_kasme, *avp_rand, *avp_autn;
#endif

    char *username = NULL;
#if 0
    uint8_t opc[OGS_KEY_LEN];
    uint8_t sqn[OGS_SQN_LEN];
    uint8_t autn[OGS_AUTN_LEN];
    uint8_t ik[OGS_KEY_LEN];
    uint8_t ck[OGS_KEY_LEN];
    uint8_t ak[OGS_AK_LEN];
    uint8_t xres[OGS_MAX_RES_LEN];
    uint8_t kasme[OGS_SHA256_DIGEST_SIZE];
    size_t xres_len = 8;

    uint8_t mac_s[OGS_MAC_S_LEN];

    ogs_dbi_auth_info_t auth_info;
    uint8_t zero[OGS_RAND_LEN];
    int rv;
#endif
    uint32_t result_code = 0;
	
    ogs_assert(msg);

    ogs_fatal("User-Authorization-Request");
	
	/* Create answer header */
	qry = *msg;
	ret = fd_msg_new_answer_from_req(fd_g_config->cnf_dict, msg, 0);
    ogs_assert(ret == 0);
    ans = *msg;

    ret = fd_msg_search_avp(qry, ogs_diam_user_name, &avp);
    ogs_assert(ret == 0);
    ret = fd_msg_avp_hdr(avp, &hdr);
    ogs_assert(ret == 0);
    username = ogs_strndup(
            (char *)hdr->avp_value->os.data,
            hdr->avp_value->os.len);
    ogs_assert(username);
    ogs_fatal("Username = %s", username);
    ogs_free(username);

    result_code = OGS_DIAM_CX_ERROR_USER_UNKNOWN;

#if 0
    rv = hss_db_auth_info(imsi_bcd, &auth_info);
    if (rv != OGS_OK) {
        result_code = OGS_DIAM_S6A_ERROR_USER_UNKNOWN;
        goto out;
    }

    memset(zero, 0, sizeof(zero));
    if (memcmp(auth_info.rand, zero, OGS_RAND_LEN) == 0) {
        ogs_random(auth_info.rand, OGS_RAND_LEN);
    }

    if (auth_info.use_opc)
        memcpy(opc, auth_info.opc, sizeof(opc));
    else
        milenage_opc(auth_info.k, auth_info.op, opc);

    ret = fd_msg_search_avp(qry, ogs_diam_cx_req_eutran_auth_info, &avp);
    ogs_assert(ret == 0);
    if (avp) {
        ret = fd_avp_search_avp(
                avp, ogs_diam_cx_re_synchronization_info, &avpch);
        ogs_assert(ret == 0);
        if (avpch) {
            ret = fd_msg_avp_hdr(avpch, &hdr);
            ogs_assert(ret == 0);
            ogs_auc_sqn(opc, auth_info.k,
                    hdr->avp_value->os.data,
                    hdr->avp_value->os.data + OGS_RAND_LEN,
                    sqn, mac_s);
            if (memcmp(mac_s, hdr->avp_value->os.data +
                        OGS_RAND_LEN + OGS_SQN_LEN, OGS_MAC_S_LEN) == 0) {
                ogs_random(auth_info.rand, OGS_RAND_LEN);
                auth_info.sqn = ogs_buffer_to_uint64(sqn, OGS_SQN_LEN);
                /* 33.102 C.3.4 Guide : IND + 1 */
                auth_info.sqn = (auth_info.sqn + 32 + 1) & OGS_MAX_SQN;
            } else {
                ogs_error("Re-synch MAC failed for IMSI:`%s`", imsi_bcd);
                ogs_log_print(OGS_LOG_ERROR, "MAC_S: ");
                ogs_log_hexdump(OGS_LOG_ERROR, mac_s, OGS_MAC_S_LEN);
                ogs_log_hexdump(OGS_LOG_ERROR,
                    (void*)(hdr->avp_value->os.data + 
                        OGS_RAND_LEN + OGS_SQN_LEN),
                    OGS_MAC_S_LEN);
                ogs_log_print(OGS_LOG_ERROR, "SQN: ");
                ogs_log_hexdump(OGS_LOG_ERROR, sqn, OGS_SQN_LEN);
                result_code = OGS_DIAM_S6A_AUTHENTICATION_DATA_UNAVAILABLE;
                goto out;
            }
        }
    }

    rv = hss_db_update_rand_and_sqn(imsi_bcd, auth_info.rand, auth_info.sqn);
    if (rv != OGS_OK) {
        ogs_error("Cannot update rand and sqn for IMSI:'%s'", imsi_bcd);
        result_code = OGS_DIAM_S6A_AUTHENTICATION_DATA_UNAVAILABLE;
        goto out;
    }

    rv = hss_db_increment_sqn(imsi_bcd);
    if (rv != OGS_OK) {
        ogs_error("Cannot increment sqn for IMSI:'%s'", imsi_bcd);
        result_code = OGS_DIAM_S6A_AUTHENTICATION_DATA_UNAVAILABLE;
        goto out;
    }

    ret = fd_msg_search_avp(qry, ogs_diam_cx_visited_plmn_id, &avp);
    ogs_assert(ret == 0);
    ret = fd_msg_avp_hdr(avp, &hdr);
    ogs_assert(ret == 0);
#if 0  // TODO : check visited_plmn_id
    memcpy(visited_plmn_id, hdr->avp_value->os.data, hdr->avp_value->os.len);
#endif

    milenage_generate(opc, auth_info.amf, auth_info.k,
        ogs_uint64_to_buffer(auth_info.sqn, OGS_SQN_LEN, sqn), auth_info.rand,
        autn, ik, ck, ak, xres, &xres_len);
    ogs_auc_kasme(ck, ik, hdr->avp_value->os.data, sqn, ak, kasme);

    /* Set the Authentication-Info */
    ret = fd_msg_avp_new(ogs_diam_cx_authentication_info, 0, &avp);
    ogs_assert(ret == 0);
    ret = fd_msg_avp_new(ogs_diam_cx_e_utran_vector, 0, &avp_e_utran_vector);
    ogs_assert(ret == 0);

    ret = fd_msg_avp_new(ogs_diam_cx_rand, 0, &avp_rand);
    ogs_assert(ret == 0);
    val.os.data = auth_info.rand;
    val.os.len = OGS_KEY_LEN;
    ret = fd_msg_avp_setvalue(avp_rand, &val);
    ogs_assert(ret == 0);
    ret = fd_msg_avp_add(avp_e_utran_vector, MSG_BRW_LAST_CHILD, avp_rand);
    ogs_assert(ret == 0);

    ret = fd_msg_avp_new(ogs_diam_cx_xres, 0, &avp_xres);
    ogs_assert(ret == 0);
    val.os.data = xres;
    val.os.len = xres_len;
    ret = fd_msg_avp_setvalue(avp_xres, &val);
    ogs_assert(ret == 0);
    ret = fd_msg_avp_add(avp_e_utran_vector, MSG_BRW_LAST_CHILD, avp_xres);
    ogs_assert(ret == 0);

    ret = fd_msg_avp_new(ogs_diam_cx_autn, 0, &avp_autn);
    ogs_assert(ret == 0);
    val.os.data = autn;
    val.os.len = OGS_AUTN_LEN;
    ret = fd_msg_avp_setvalue(avp_autn, &val);
    ogs_assert(ret == 0);
    ret = fd_msg_avp_add(avp_e_utran_vector, MSG_BRW_LAST_CHILD, avp_autn);
    ogs_assert(ret == 0);

    ret = fd_msg_avp_new(ogs_diam_cx_kasme, 0, &avp_kasme);
    ogs_assert(ret == 0);
    val.os.data = kasme;
    val.os.len = OGS_SHA256_DIGEST_SIZE;
    ret = fd_msg_avp_setvalue(avp_kasme, &val);
    ogs_assert(ret == 0);
    ret = fd_msg_avp_add(avp_e_utran_vector, MSG_BRW_LAST_CHILD, avp_kasme);
    ogs_assert(ret == 0);

    ret = fd_msg_avp_add(avp, MSG_BRW_LAST_CHILD, avp_e_utran_vector);
    ogs_assert(ret == 0);
    ret = fd_msg_avp_add(ans, MSG_BRW_LAST_CHILD, avp);
    ogs_assert(ret == 0);

	/* Set the Origin-Host, Origin-Realm, andResult-Code AVPs */
	ret = fd_msg_rescode_set(ans, (char*)"DIAMETER_SUCCESS", NULL, NULL, 1);
    ogs_assert(ret == 0);

    /* Set the Auth-Session-State AVP */
    ret = fd_msg_avp_new(ogs_diam_auth_session_state, 0, &avp);
    ogs_assert(ret == 0);
    val.i32 = 1;
    ret = fd_msg_avp_setvalue(avp, &val);
    ogs_assert(ret == 0);
    ret = fd_msg_avp_add(ans, MSG_BRW_LAST_CHILD, avp);
    ogs_assert(ret == 0);

    /* Set Vendor-Specific-Application-Id AVP */
    ret = ogs_diam_message_vendor_specific_appid_set(
            ans, OGS_DIAM_S6A_APPLICATION_ID);
    ogs_assert(ret == 0);

	/* Send the answer */
	ret = fd_msg_send(msg, NULL, NULL);
    ogs_assert(ret == 0);

    ogs_debug("[HSS] Authentication-Information-Answer");
	
	/* Add this value to the stats */
	ogs_assert(pthread_mutex_lock(&ogs_diam_logger_self()->stats_lock) == 0);
	ogs_diam_logger_self()->stats.nb_echoed++;
	ogs_assert(pthread_mutex_unlock(&ogs_diam_logger_self()->stats_lock) == 0);

	return 0;
#endif

out:
    ret = ogs_diam_message_experimental_rescode_set(ans, result_code);
    ogs_assert(ret == 0);

    /* Set the Auth-Session-State AVP */
    ret = fd_msg_avp_new(ogs_diam_auth_session_state, 0, &avp);
    ogs_assert(ret == 0);
    val.i32 = 1;
    ret = fd_msg_avp_setvalue(avp, &val);
    ogs_assert(ret == 0);
    ret = fd_msg_avp_add(ans, MSG_BRW_LAST_CHILD, avp);
    ogs_assert(ret == 0);

    /* Set Vendor-Specific-Application-Id AVP */
    ret = ogs_diam_message_vendor_specific_appid_set(
            ans, OGS_DIAM_S6A_APPLICATION_ID);
    ogs_assert(ret == 0);

	ret = fd_msg_send(msg, NULL, NULL);
    ogs_assert(ret == 0);

    return 0;
}

int hss_cx_init(void)
{
    int ret;
	struct disp_when data;

	/* Install objects definitions for this application */
	ret = ogs_diam_cx_init();
    ogs_assert(ret == 0);

	memset(&data, 0, sizeof(data));
	data.app = ogs_diam_cx_application;
	
	/* Fallback CB if command != unexpected message received */
	ret = fd_disp_register(hss_ogs_diam_cx_fb_cb, DISP_HOW_APPID,
                                &data, NULL, &hdl_cx_fb);
    ogs_assert(ret == 0);
	
	/* Specific handler for User-Authorization-Request */
	data.command = ogs_diam_cx_cmd_uar;
	ret = fd_disp_register(hss_ogs_diam_cx_uar_cb, DISP_HOW_CC, &data, NULL,
                &hdl_cx_uar);
    ogs_assert(ret == 0);

	/* Advertise the support for the application in the peer */
	ret = fd_disp_app_support(ogs_diam_cx_application, ogs_diam_vendor, 1, 0);
    ogs_assert(ret == 0);

	return OGS_OK;
}

void hss_cx_final(void)
{
	if (hdl_cx_fb)
		(void) fd_disp_unregister(&hdl_cx_fb, NULL);
	if (hdl_cx_uar)
		(void) fd_disp_unregister(&hdl_cx_uar, NULL);
}

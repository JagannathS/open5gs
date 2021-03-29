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

#define CHECK_dict_search( _type, _criteria, _what, _result )	\
	CHECK_FCT(  fd_dict_search( fd_g_config->cnf_dict, (_type), (_criteria), (_what), (_result), ENOENT) );

struct dict_object *ogs_diam_cx_application = NULL;

struct dict_object *ogs_diam_cx_cmd_uar = NULL;
struct dict_object *ogs_diam_cx_cmd_uaa = NULL;

struct dict_object *ogs_diam_cx_public_identity = NULL;
struct dict_object *ogs_diam_cx_visited_network_identifier = NULL;
struct dict_object *ogs_diam_cx_server_name = NULL;

extern int ogs_dict_cx_entry(char *conffile);

int ogs_diam_cx_init(void)
{
    application_id_t id = OGS_DIAM_CX_APPLICATION_ID;

    ogs_assert(ogs_dict_cx_entry(NULL) == 0);

    CHECK_dict_search(DICT_APPLICATION, APPLICATION_BY_ID,
            (void *)&id, &ogs_diam_cx_application);

    CHECK_dict_search(DICT_COMMAND, CMD_BY_NAME,
            "3GPP/User-Authorization-Request", &ogs_diam_cx_cmd_uar);
    CHECK_dict_search(DICT_COMMAND, CMD_BY_NAME,
            "3GPP/User-Authorization-Answer", &ogs_diam_cx_cmd_uaa);

    CHECK_dict_search(DICT_AVP, AVP_BY_NAME_ALL_VENDORS,
            "Public-Identity", &ogs_diam_cx_public_identity);
    CHECK_dict_search(DICT_AVP, AVP_BY_NAME_ALL_VENDORS,
            "Visited-Network-Identifier",
            &ogs_diam_cx_visited_network_identifier);
    CHECK_dict_search(DICT_AVP, AVP_BY_NAME_ALL_VENDORS,
            "Server-Name", &ogs_diam_cx_server_name);

    return 0;
}

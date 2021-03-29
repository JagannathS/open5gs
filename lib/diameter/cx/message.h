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

#if !defined(OGS_DIAMETER_INSIDE) && !defined(OGS_DIAMETER_COMPILATION)
#error "This header cannot be included directly."
#endif

#ifndef OGS_DIAM_CX_MESSAGE_H
#define OGS_DIAM_CX_MESSAGE_H

#ifdef __cplusplus
extern "C" {
#endif

#define OGS_DIAM_CX_APPLICATION_ID 16777216

extern struct dict_object *ogs_diam_cx_application;

extern struct dict_object *ogs_diam_cx_cmd_uar;
extern struct dict_object *ogs_diam_cx_cmd_uaa;

extern struct dict_object *ogs_diam_cx_public_identity;
extern struct dict_object *ogs_diam_cx_visited_network_identifier;
extern struct dict_object *ogs_diam_cx_server_name;

int ogs_diam_cx_init(void);

#define OGS_DIAM_CX_FIRST_REGISTRATION                      2001
#define OGS_DIAM_CX_SUBSEQUENT_REGISTRATION                 2002
#define OGS_DIAM_CX_UNREGISTERED_SERVICE                    2003
#define OGS_DIAM_CX_SERVER_NAME_NOT_STORED                  2004
#define OGS_DIAM_CX_ERROR_USER_UNKNOWN                      5001
#define OGS_DIAM_CX_ERROR_IDENTITIES_DONT_MATCH             5002
#define OGS_DIAM_CX_ERROR_IDENTITY_NOT_REGISTERED           5003
#define OGS_DIAM_CX_ERROR_ROAMING_NOT_ALLOWED               5004
#define OGS_DIAM_CX_ERROR_IDENTITY_ALREADY_REGISTERED       5005
#define OGS_DIAM_CX_ERROR_AUTH_SCHEME_NOT_SUPPORTED         5006
#define OGS_DIAM_CX_ERROR_IN_ASSIGNMENT_TYPE                5007
#define OGS_DIAM_CX_ERROR_TOO_MUCH_DATA                     5008
#define OGS_DIAM_CX_ERROR_NOT_SUPPORTED_USER_DATA           5009
#define OGS_DIAM_CX_ERROR_FEATURE_UNSUPPORTED               5011
#define OGS_DIAM_CX_ERROR_SERVING_NODE_FEATURE_UNSUPPORTED  5012

#ifdef __cplusplus
}
#endif

#endif /* OGS_DIAM_OGS_DIAM_CX_MESSAGE_H */

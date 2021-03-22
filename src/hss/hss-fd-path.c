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

int hss_fd_init(void)
{
    int rv, ret;
    struct dict_object *s6a_app, *vnd;
    struct dict_vendor_data vnd_data;
    struct dict_application_data s6a_app_data;

    ret = ogs_diam_init(FD_MODE_SERVER,
                hss_self()->diam_conf_path, hss_self()->diam_config);
    ogs_assert(ret == 0);

    vnd_data.vendor_id = OGS_3GPP_VENDOR_ID;
    vnd_data.vendor_name = (char *) "3GPP";

    ret = fd_dict_new(fd_g_config->cnf_dict,
            DICT_VENDOR, &vnd_data, NULL, &vnd);
    ogs_assert(ret == 0);

    s6a_app_data.application_id = OGS_DIAM_S6A_APPLICATION_ID;
    s6a_app_data.application_name = (char *) "S6A";

    ret = fd_dict_new(fd_g_config->cnf_dict, DICT_APPLICATION,
            &s6a_app_data, NULL, &s6a_app);
    ogs_assert(ret == 0);

    ret = fd_disp_app_support(s6a_app, vnd, 1, 0);
    ogs_assert(ret == 0);

    rv = hss_s6a_init();
    ogs_assert(rv == OGS_OK);

	return OGS_OK;
}

void hss_fd_final(void)
{
    hss_s6a_final();

    ogs_diam_final();
}

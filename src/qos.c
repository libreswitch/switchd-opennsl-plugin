
/*
 * Copyright (C) 2016 Hewlett-Packard Enterprise Development LP
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <unistd.h>
#include "openvswitch/vlog.h"
#include "ofproto/ofproto-provider.h"
#include "qos.h"

VLOG_DEFINE_THIS_MODULE(qos_module);

int
set_port_qos_cfg(struct ofproto *ofproto, void *aux,
                     const struct qos_port_settings *settings)
{
    return -1;
}

int
set_cos_map(struct ofproto *ofproto, const void *aux,
            const struct cos_map_settings *settings)
{
    return -1;
}

int
set_dscp_map(struct ofproto *ofproto, void *aux,
                 const struct dscp_map_settings *settings)
{
    return -1;
}

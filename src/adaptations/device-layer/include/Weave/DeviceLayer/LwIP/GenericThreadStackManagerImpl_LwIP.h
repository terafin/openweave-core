/*
 *
 *    Copyright (c) 2019 Nest Labs, Inc.
 *    All rights reserved.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

/**
 *    @file
 *          Provides a generic implementation of ThreadStackManager features
 *          for use on platforms that use OpenThread with LwIP.
 */

#ifndef GENERIC_THREAD_STACK_MANAGER_IMPL_LWIP_H
#define GENERIC_THREAD_STACK_MANAGER_IMPL_LWIP_H

#include <lwip/tcpip.h>
#include <lwip/netif.h>

#include <openthread/message.h>

namespace nl {
namespace Weave {
namespace DeviceLayer {
namespace Internal {

/**
 * Provides a generic implementation of ThreadStackManager features that works in conjunction
 * with OpenThread and LwIP.
 *
 * This template contains implementations of select features from the ThreadStackManager abstract
 * interface that are suitable for use on devices that employ OpenThread and LwIP together.  It is
 * intended to be inherited, directly or indirectly, by the ThreadStackManagerImpl class, which
 * also appears as the template's ImplClass parameter.
 */
template<class ImplClass>
class GenericThreadStackManagerImpl_LwIP
{
public:

    // ===== Platform-specific methods directly callable by the application.

    struct netif * ThreadNetIf() const;

protected:

    // ===== Members available to the implementation subclass.

    WEAVE_ERROR InitThreadNetIf(void);
    WEAVE_ERROR UpdateThreadNetIfState(void);

private:

    // ===== Private members for use by this class only.

    struct netif * mNetIf;
    bool mAddrAssigned[LWIP_IPV6_NUM_ADDRESSES];

    static err_t DoInitThreadNetIf(struct netif * netif);
#if LWIP_VERSION_MAJOR < 2
    static err_t SendPacket(struct netif * netif, struct pbuf * pkt, struct ip6_addr * ipaddr);
#else
    static err_t SendPacket(struct netif * netif, struct pbuf * pkt, const struct ip6_addr * ipaddr);
#endif
    static void ReceivePacket(otMessage * pkt, void * context);

    inline ImplClass * Impl() { return static_cast<ImplClass*>(this); }
};

template<class ImplClass>
inline struct netif * GenericThreadStackManagerImpl_LwIP<ImplClass>::ThreadNetIf() const
{
    return mNetIf;
}

} // namespace Internal
} // namespace DeviceLayer
} // namespace Weave
} // namespace nl

#endif // GENERIC_THREAD_STACK_MANAGER_IMPL_LWIP_H

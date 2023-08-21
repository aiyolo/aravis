/* Aravis - Digital camera library
 *
 * Copyright © 2009-2022 Emmanuel Pacaud
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * Public License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 * Author: Emmanuel Pacaud <emmanuel.pacaud@free.fr>
 */

/**
 * SECTION: arvgvinterface
 * @short_description: GigEVision interface
 */

#include <arvgvinterfaceprivate.h>
#include <arvinterfaceprivate.h>
#include <arvgvdeviceprivate.h>
#include <arvgvcpprivate.h>
#include <arvdebugprivate.h>
#include <arvmisc.h>
#include <arvmiscprivate.h>
#include <arvnetworkprivate.h>
#include <arvstr.h>
#include <glib/gprintf.h>
#include <gio/gio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>

/* ArvGvDiscoverSocket implementation */
// 设备发现相关的socket
typedef struct
{
    GSocketAddress *interface_address;
    GSocketAddress *broadcast_address;
    GSocket *socket;
} ArvGvDiscoverSocket;

// 将设备发现socket设置成广播类型
static gboolean arv_gv_discover_socket_set_broadcast(ArvGvDiscoverSocket *discover_socket, gboolean enable)
{
    int socket_fd;
    int result;

    socket_fd = g_socket_get_fd(discover_socket->socket);

    result = setsockopt(socket_fd, SOL_SOCKET, SO_BROADCAST, (char *)&enable, sizeof(enable));

    return result == 0;
}

typedef struct
{
    unsigned int n_sockets;
    GSList *sockets;
    GPollFD *poll_fds;
} ArvGvDiscoverSocketList;

static ArvGvDiscoverSocketList *arv_gv_discover_socket_list_new(void)
{
    ArvGvDiscoverSocketList *socket_list;
    GSList *iter;
    GList *ifaces;
    GList *iface_iter;
    int i;

    socket_list = g_new0(ArvGvDiscoverSocketList, 1);
    // 枚举网络接口
    ifaces = arv_enumerate_network_interfaces();
    if (!ifaces)
        return socket_list;

    for (iface_iter = ifaces; iface_iter != NULL; iface_iter = iface_iter->next)
    {
        ArvGvDiscoverSocket *discover_socket = g_new0(ArvGvDiscoverSocket, 1);
        GSocketAddress *socket_address;
        GSocketAddress *socket_broadcast;
        GInetAddress *inet_address;
        GInetAddress *inet_broadcast;
        char *inet_address_string;
        char *inet_broadcast_string;
        GError *error = NULL;
        gint buffer_size = ARV_GV_INTERFACE_DISCOVERY_SOCKET_BUFFER_SIZE;
        // 创建和获取网络接口地址和广播地址
        socket_address = g_socket_address_new_from_native(arv_network_interface_get_addr(iface_iter->data), sizeof(struct sockaddr));
        socket_broadcast = g_socket_address_new_from_native(arv_network_interface_get_broadaddr(iface_iter->data), sizeof(struct sockaddr));
        // 将socket_address转成inet_address类型
        inet_address = g_inet_socket_address_get_address(G_INET_SOCKET_ADDRESS(socket_address));
        inet_broadcast = g_inet_socket_address_get_address(G_INET_SOCKET_ADDRESS(socket_broadcast));
        inet_address_string = g_inet_address_to_string(inet_address);
        inet_broadcast_string = g_inet_address_to_string(inet_broadcast);
        arv_info_interface("[GvDiscoverSocket::new] Add interface %s (%s)", inet_address_string, inet_broadcast_string);
        g_free(inet_address_string);
        g_free(inet_broadcast_string);
        // 将地址赋值给 discover_socket
        discover_socket->interface_address = g_inet_socket_address_new(inet_address, 0);
        discover_socket->broadcast_address = g_inet_socket_address_new(inet_broadcast, ARV_GVCP_PORT);
        g_object_unref(socket_address);
        g_object_unref(socket_broadcast);
        // 创建socket
        discover_socket->socket =
            g_socket_new(g_inet_address_get_family(inet_address), G_SOCKET_TYPE_DATAGRAM, G_SOCKET_PROTOCOL_UDP, NULL);
        // 设置接受大小 256*1024
        arv_socket_set_recv_buffer_size(g_socket_get_fd(discover_socket->socket), buffer_size);
        // 将socket绑定到接口地址，不重用地址
        g_socket_bind(discover_socket->socket, discover_socket->interface_address, FALSE, &error);
        // 将socket添加到socket链表
        socket_list->sockets = g_slist_prepend(socket_list->sockets, discover_socket);
        socket_list->n_sockets++;
    }
    g_list_free_full(ifaces, (GDestroyNotify)arv_network_interface_free);
    // 监听这些socket上的事件
    socket_list->poll_fds = g_new(GPollFD, socket_list->n_sockets);
    for (i = 0, iter = socket_list->sockets; iter != NULL; i++, iter = iter->next)
    {
        ArvGvDiscoverSocket *discover_socket = iter->data;

        socket_list->poll_fds[i].fd = g_socket_get_fd(discover_socket->socket);
        socket_list->poll_fds[i].events = G_IO_IN;
        socket_list->poll_fds[i].revents = 0;
    }

    arv_gpollfd_prepare_all(socket_list->poll_fds, socket_list->n_sockets);

    return socket_list;
}

static void arv_gv_discover_socket_list_free(ArvGvDiscoverSocketList *socket_list)
{
    GSList *iter;

    g_return_if_fail(socket_list != NULL);

    arv_gpollfd_finish_all(socket_list->poll_fds, socket_list->n_sockets);

    for (iter = socket_list->sockets; iter != NULL; iter = iter->next)
    {
        ArvGvDiscoverSocket *discover_socket = iter->data;

        g_object_unref(discover_socket->interface_address);
        g_object_unref(discover_socket->broadcast_address);
        g_object_unref(discover_socket->socket);
        g_free(discover_socket);
    }
    g_slist_free(socket_list->sockets);
    g_free(socket_list->poll_fds);

    socket_list->sockets = NULL;
    socket_list->n_sockets = 0;
    socket_list->poll_fds = NULL;

    g_free(socket_list);
}

static void arv_gv_discover_socket_list_send_discover_packet(ArvGvDiscoverSocketList *socket_list, gboolean allow_broadcast_discovery_ack)
{
    GInetAddress *broadcast_address;
    GSocketAddress *broadcast_socket_address;
    ArvGvcpPacket *packet;
    GSList *iter;
    size_t size;

    // 创建设备发现控制包
    packet = arv_gvcp_packet_new_discovery_cmd(allow_broadcast_discovery_ack, &size);

    // 广播地址，端口3956
    broadcast_address = g_inet_address_new_from_string("255.255.255.255");
    broadcast_socket_address = g_inet_socket_address_new(broadcast_address, ARV_GVCP_PORT);
    g_object_unref(broadcast_address);

    for (iter = socket_list->sockets; iter != NULL; iter = iter->next)
    {
        ArvGvDiscoverSocket *discover_socket = iter->data;
        GError *error = NULL;
        // 给监听socket 设置广播属性
        arv_gv_discover_socket_set_broadcast(discover_socket, TRUE);
        // 将设备发现包发送到广播地址
        g_socket_send_to(discover_socket->socket, broadcast_socket_address, (const char *)packet, size, NULL, &error);
        // 出错的话，重试两次
        if (error != NULL)
        {
            arv_warning_interface("[ArvGVInterface::send_discover_packet] "
                                  "Error sending packet using local broadcast: %s",
                error->message);
            g_clear_error(&error);

            g_socket_send_to(discover_socket->socket, discover_socket->broadcast_address, (const char *)packet, size, NULL, &error);

            if (error != NULL)
            {
                arv_warning_interface("[ArvGVInterface::send_discover_packet] "
                                      "Error sending packet using directed broadcast: %s",
                    error->message);
                g_clear_error(&error);
            }
        }

        arv_gv_discover_socket_set_broadcast(discover_socket, FALSE);
    }

    g_object_unref(broadcast_socket_address);

    arv_gvcp_packet_free(packet);
}

/* ArvGvInterfaceDeviceInfos implementation */

typedef struct
{
    char *id;
    char *user_id;
    char *vendor_serial;
    char *vendor_alias_serial;
    char *vendor;
    char *manufacturer_info;
    char *model;
    char *serial;
    char *mac;

    GInetAddress *interface_address;

    guchar discovery_data[ARV_GVBS_DISCOVERY_DATA_SIZE];

    volatile gint ref_count;
} ArvGvInterfaceDeviceInfos;

static ArvGvInterfaceDeviceInfos *arv_gv_interface_device_infos_new(GInetAddress *interface_address, void *discovery_data)
{
    ArvGvInterfaceDeviceInfos *infos;

    g_return_val_if_fail(G_IS_INET_ADDRESS(interface_address), NULL);
    g_return_val_if_fail(discovery_data != NULL, NULL);

    g_object_ref(interface_address);

    infos = g_new0(ArvGvInterfaceDeviceInfos, 1);
    // 将dicovery_data拷贝到info结构体，大小为0xf8
    memcpy(infos->discovery_data, discovery_data, ARV_GVBS_DISCOVERY_DATA_SIZE);
    // 拷贝其他数据
    infos->vendor = g_strndup((char *)&infos->discovery_data[ARV_GVBS_MANUFACTURER_NAME_OFFSET], ARV_GVBS_MANUFACTURER_NAME_SIZE);
    infos->manufacturer_info =
        g_strndup((char *)&infos->discovery_data[ARV_GVBS_MANUFACTURER_INFO_OFFSET], ARV_GVBS_MANUFACTURER_INFO_SIZE);
    infos->model = g_strndup((char *)&infos->discovery_data[ARV_GVBS_MODEL_NAME_OFFSET], ARV_GVBS_MODEL_NAME_SIZE);
    infos->serial = g_strndup((char *)&infos->discovery_data[ARV_GVBS_SERIAL_NUMBER_OFFSET], ARV_GVBS_SERIAL_NUMBER_SIZE);
    infos->user_id = g_strndup((char *)&infos->discovery_data[ARV_GVBS_USER_DEFINED_NAME_OFFSET], ARV_GVBS_USER_DEFINED_NAME_SIZE);
    infos->mac = g_strdup_printf("%02x:%02x:%02x:%02x:%02x:%02x", infos->discovery_data[ARV_GVBS_DEVICE_MAC_ADDRESS_HIGH_OFFSET + 2],
        infos->discovery_data[ARV_GVBS_DEVICE_MAC_ADDRESS_HIGH_OFFSET + 3],
        infos->discovery_data[ARV_GVBS_DEVICE_MAC_ADDRESS_HIGH_OFFSET + 4],
        infos->discovery_data[ARV_GVBS_DEVICE_MAC_ADDRESS_HIGH_OFFSET + 5],
        infos->discovery_data[ARV_GVBS_DEVICE_MAC_ADDRESS_HIGH_OFFSET + 6],
        infos->discovery_data[ARV_GVBS_DEVICE_MAC_ADDRESS_HIGH_OFFSET + 7]);

    /* Some devices return a zero length string as the serial identifier.
     * Use the MAC address as the serial number in this case */

    if (infos->serial == NULL || infos->serial[0] == '\0')
    {
        g_free(infos->serial);
        infos->serial = g_strdup(infos->mac);
    }

    infos->id = g_strdup_printf("%s-%s-%s", infos->vendor, infos->model, infos->serial);
    arv_str_strip(infos->id, ARV_DEVICE_NAME_ILLEGAL_CHARACTERS, ARV_DEVICE_NAME_REPLACEMENT_CHARACTER);

    infos->vendor_alias_serial = g_strdup_printf("%s-%s", arv_vendor_alias_lookup(infos->vendor), infos->serial);
    arv_str_strip(infos->vendor_alias_serial, ARV_DEVICE_NAME_ILLEGAL_CHARACTERS, ARV_DEVICE_NAME_REPLACEMENT_CHARACTER);

    infos->vendor_serial = g_strdup_printf("%s-%s", infos->vendor, infos->serial);
    arv_str_strip(infos->vendor_serial, ARV_DEVICE_NAME_ILLEGAL_CHARACTERS, ARV_DEVICE_NAME_REPLACEMENT_CHARACTER);

    infos->interface_address = interface_address;

    infos->ref_count = 1;

    return infos;
}

static ArvGvInterfaceDeviceInfos *arv_gv_interface_device_infos_ref(ArvGvInterfaceDeviceInfos *infos)
{
    g_return_val_if_fail(infos != NULL, NULL);
    g_return_val_if_fail(g_atomic_int_get(&infos->ref_count) > 0, NULL);

    g_atomic_int_inc(&infos->ref_count);

    return infos;
}

static void arv_gv_interface_device_infos_unref(ArvGvInterfaceDeviceInfos *infos)
{
    g_return_if_fail(infos != NULL);
    g_return_if_fail(g_atomic_int_get(&infos->ref_count) > 0);

    if (g_atomic_int_dec_and_test(&infos->ref_count))
    {
        g_object_unref(infos->interface_address);
        g_free(infos->id);
        g_free(infos->user_id);
        g_free(infos->vendor_serial);
        g_free(infos->vendor_alias_serial);
        g_free(infos->vendor);
        g_free(infos->manufacturer_info);
        g_free(infos->model);
        g_free(infos->serial);
        g_free(infos->mac);
        g_free(infos);
    }
}

/* ArvGvInterface implementation */

typedef struct
{
    GHashTable *devices;
} ArvGvInterfacePrivate;

struct _ArvGvInterface
{
    ArvInterface interface;

    ArvGvInterfacePrivate *priv;
};

// 父类是 ArvInterfaceClass
struct _ArvGvInterfaceClass
{
    ArvInterfaceClass parent_class;
};

G_DEFINE_TYPE_WITH_CODE(ArvGvInterface, arv_gv_interface, ARV_TYPE_INTERFACE, G_ADD_PRIVATE(ArvGvInterface))

static ArvGvInterfaceDeviceInfos *_discover(GHashTable *devices, const char *device_id, gboolean allow_broadcast_discovery_ack)
{
    ArvGvDiscoverSocketList *socket_list;
    GSList *iter;
    char buffer[ARV_GV_INTERFACE_SOCKET_BUFFER_SIZE];
    int count;
    int i;

    g_assert(devices == NULL || device_id == NULL);

    if (devices != NULL)
        g_hash_table_remove_all(devices);

    // 创建socket_list 监听列表
    socket_list = arv_gv_discover_socket_list_new();

    if (socket_list->n_sockets < 1)
    {
        arv_gv_discover_socket_list_free(socket_list);
        return NULL;
    }
    // 发送探测包
    arv_gv_discover_socket_list_send_discover_packet(socket_list, allow_broadcast_discovery_ack);
    // 死循环
    do
    {
        gint res;

        res = g_poll(socket_list->poll_fds, socket_list->n_sockets, ARV_GV_INTERFACE_DISCOVERY_TIMEOUT_MS);
        if (res <= 0)
        {
            arv_gv_discover_socket_list_free(socket_list);

            /* Timeout case */
            if (res == 0)
                return NULL;

            g_critical("g_poll returned %d (call was interrupted)", res);

            return NULL;
        }

        for (i = 0, iter = socket_list->sockets; iter != NULL; i++, iter = iter->next)
        {
            ArvGvDiscoverSocket *discover_socket = iter->data;

            arv_gpollfd_clear_one(&socket_list->poll_fds[i], discover_socket->socket);

            // 循环收包
            do
            {
                // 非阻塞收取
                g_socket_set_blocking(discover_socket->socket, FALSE);

                // 1024字节
                count = g_socket_receive(discover_socket->socket, buffer, ARV_GV_INTERFACE_SOCKET_BUFFER_SIZE, NULL, NULL);
                g_socket_set_blocking(discover_socket->socket, TRUE);
                // 如果没有收取到报文，那么进行下一个socket收取
                if (count > 0)
                {
                    ArvGvcpPacket *packet = (ArvGvcpPacket *)buffer;
                    // ack报文 && 0xffff
                    if (g_ntohs(packet->header.command) == ARV_GVCP_COMMAND_DISCOVERY_ACK && g_ntohs(packet->header.id) == 0xffff)
                    {
                        ArvGvInterfaceDeviceInfos *device_infos;
                        GInetAddress *interface_address;
                        char *address_string;
                        // data从buffer第八个字节开始，data可以访问ArvGvcpHeader结构体后面的数据
                        char *data = buffer + sizeof(ArvGvcpHeader);

                        arv_gvcp_packet_debug(packet, ARV_DEBUG_LEVEL_DEBUG);

                        interface_address = g_inet_socket_address_get_address(G_INET_SOCKET_ADDRESS(discover_socket->interface_address));
                        // 将ack数据包data中的信息填充到device_info中
                        device_infos = arv_gv_interface_device_infos_new(interface_address, data);
                        address_string = g_inet_address_to_string(interface_address);

                        arv_info_interface("[GvInterface::discovery] Device '%s' found "
                                           "(interface %s) user_id '%s' - MAC '%s'",
                            device_infos->id, address_string, device_infos->user_id, device_infos->mac);

                        g_free(address_string);

                        if (devices != NULL)
                        {
                            if (device_infos->id != NULL && device_infos->id[0] != '\0')
                                g_hash_table_replace(devices, device_infos->id, arv_gv_interface_device_infos_ref(device_infos));
                            if (device_infos->user_id != NULL && device_infos->user_id[0] != '\0')
                                g_hash_table_replace(devices, device_infos->user_id, arv_gv_interface_device_infos_ref(device_infos));
                            if (device_infos->vendor_serial != NULL && device_infos->vendor_serial[0] != '\0')
                                g_hash_table_replace(devices, device_infos->vendor_serial, arv_gv_interface_device_infos_ref(device_infos));
                            if (device_infos->vendor_alias_serial != NULL && device_infos->vendor_alias_serial[0] != '\0')
                                g_hash_table_replace(
                                    devices, device_infos->vendor_alias_serial, arv_gv_interface_device_infos_ref(device_infos));
                            g_hash_table_replace(devices, device_infos->mac, arv_gv_interface_device_infos_ref(device_infos));
                        }
                        else
                        {
                            if (device_id == NULL || g_strcmp0(device_infos->id, device_id) == 0 ||
                                g_strcmp0(device_infos->user_id, device_id) == 0 ||
                                g_strcmp0(device_infos->vendor_serial, device_id) == 0 ||
                                g_strcmp0(device_infos->vendor_alias_serial, device_id) == 0 ||
                                g_strcmp0(device_infos->mac, device_id) == 0)
                            {
                                arv_gv_discover_socket_list_free(socket_list);

                                return device_infos;
                            }
                        }

                        arv_gv_interface_device_infos_unref(device_infos);
                    }
                }
            } while (count > 0);
        }
    } while (1);
}

static void arv_gv_interface_discover(ArvGvInterface *gv_interface)
{
    int flags = arv_interface_get_flags(ARV_INTERFACE(gv_interface));
	// 发现的设备保存到 gv_interface->priv->devices, 类型为哈希表
    _discover(gv_interface->priv->devices, NULL, flags & ARV_GV_INTERFACE_FLAGS_ALLOW_BROADCAST_DISCOVERY_ACK);
}

static GInetAddress *_device_infos_to_ginetaddress(ArvGvInterfaceDeviceInfos *device_infos)
{
    GInetAddress *device_address;

    device_address = g_inet_address_new_from_bytes(&device_infos->discovery_data[ARV_GVBS_CURRENT_IP_ADDRESS_OFFSET], G_SOCKET_FAMILY_IPV4);

    return device_address;
}

// 把接口的device_list 添加到 devices_ids列表
static void arv_gv_interface_update_device_list(ArvInterface *interface, GArray *device_ids)
{
    ArvGvInterface *gv_interface;
    GHashTableIter iter;
    gpointer key, value;

    g_assert(device_ids->len == 0);

    gv_interface = ARV_GV_INTERFACE(interface);

	// 发现设备
    arv_gv_interface_discover(gv_interface);

    g_hash_table_iter_init(&iter, gv_interface->priv->devices);
    while (g_hash_table_iter_next(&iter, &key, &value)) // ((char *)key, device_info)
    {
        ArvGvInterfaceDeviceInfos *infos = value;
		// 如果key是infos->id
        if (g_strcmp0(key, infos->id) == 0)
        {
            ArvInterfaceDeviceIds *ids;
            GInetAddress *device_address;

            device_address = _device_infos_to_ginetaddress(infos);

            ids = g_new0(ArvInterfaceDeviceIds, 1);
            ids->device = g_strdup(key);
            ids->physical = g_strdup(infos->mac);
            ids->address = g_inet_address_to_string(device_address);
            ids->vendor = g_strdup(infos->vendor);
            ids->manufacturer_info = g_strdup(infos->manufacturer_info);
            ids->model = g_strdup(infos->model);
            ids->serial_nbr = g_strdup(infos->serial);
			// 添加到device_ids列表
            g_array_append_val(device_ids, ids);

            g_object_unref(device_address);
        }
    }
}

// 定位相机
static GInetAddress *arv_gv_interface_camera_locate(ArvGvInterface *gv_interface, GInetAddress *device_address)
{
    ArvGvDiscoverSocketList *socket_list;
    ArvGvcpPacket *packet;
    char buffer[ARV_GV_INTERFACE_SOCKET_BUFFER_SIZE];
    GSList *iter;
    GSocketAddress *device_socket_address;
    size_t size;
    int i, count;
    GList *ifaces;
    GList *iface_iter;
    struct sockaddr_in device_sockaddr;
	// 创建 目标地址 3956端口的ip地址
    device_socket_address = g_inet_socket_address_new(device_address, ARV_GVCP_PORT);

    ifaces = arv_enumerate_network_interfaces();
    if (ifaces)
    {
        g_socket_address_to_native(device_socket_address, &device_sockaddr, sizeof(device_sockaddr), NULL);

        for (iface_iter = ifaces; iface_iter != NULL; iface_iter = iface_iter->next)
        {
			// 获取接口地址和子网掩码
            struct sockaddr_in *sa = (struct sockaddr_in *)arv_network_interface_get_addr(iface_iter->data);
            struct sockaddr_in *mask = (struct sockaddr_in *)arv_network_interface_get_netmask(iface_iter->data);
			// 目标设备地址与接口地址在一个网段下
            if ((sa->sin_addr.s_addr & mask->sin_addr.s_addr) == (device_sockaddr.sin_addr.s_addr & mask->sin_addr.s_addr))
            {
                GSocketAddress *socket_address =
                    g_socket_address_new_from_native(arv_network_interface_get_addr(iface_iter->data), sizeof(struct sockaddr));
				// 得到 接口的 inet地址
                GInetAddress *inet_address = g_object_ref(g_inet_socket_address_get_address(G_INET_SOCKET_ADDRESS(socket_address)));

                g_list_free_full(ifaces, (GDestroyNotify)arv_network_interface_free);

                g_object_unref(socket_address);
                g_object_unref(device_socket_address);

                return inet_address;
            }
        }
        g_list_free_full(ifaces, (GDestroyNotify)arv_network_interface_free);
    }

    socket_list = arv_gv_discover_socket_list_new();

    if (socket_list->n_sockets < 1)
    {
        arv_gv_discover_socket_list_free(socket_list);
        return NULL;
    }

    /* Just read a random register from the camera socket */
	// 创建读寄存器包,数据地址为ARV_GVBS_N_STREAM_CHANNELS_OFFSET
    packet = arv_gvcp_packet_new_read_register_cmd(ARV_GVBS_N_STREAM_CHANNELS_OFFSET, 0, &size);

    for (iter = socket_list->sockets; iter != NULL; iter = iter->next)
    {
        ArvGvDiscoverSocket *socket = iter->data;
        GError *error = NULL;
		// 通过接口socket发送数据到设备目标地址
        g_socket_send_to(socket->socket, device_socket_address, (const char *)packet, size, NULL, &error);
        if (error != NULL)
        {
            arv_warning_interface("[ArvGVInterface::arv_gv_interface_camera_locate] Error: %s", error->message);
            g_error_free(error);
        }
    }

    g_object_unref(device_socket_address);

    arv_gvcp_packet_free(packet);

    do
    {
        /* Now parse the result */
        if (g_poll(socket_list->poll_fds, socket_list->n_sockets, ARV_GV_INTERFACE_DISCOVERY_TIMEOUT_MS) == 0)
        {
            arv_gv_discover_socket_list_free(socket_list);
            return NULL;
        }

        for (i = 0, iter = socket_list->sockets; iter != NULL; i++, iter = iter->next)
        {
            ArvGvDiscoverSocket *socket = iter->data;

            arv_gpollfd_clear_one(&socket_list->poll_fds[i], socket->socket);

            do
            {
                g_socket_set_blocking(socket->socket, FALSE);
				// 收数据
                count = g_socket_receive(socket->socket, buffer, ARV_GV_INTERFACE_SOCKET_BUFFER_SIZE, NULL, NULL);
                g_socket_set_blocking(socket->socket, TRUE);
				// 根据接收到的数据包内容，判断是否满足特定条件，如果满足，则获取网络地址信息，并进行一些处理，最后返回获取到的网络地址。
                if (count > 0)
                {
                    ArvGvcpPacket *packet = (ArvGvcpPacket *)buffer;

                    if (g_ntohs(packet->header.command) == ARV_GVCP_COMMAND_READ_REGISTER_CMD ||
                        g_ntohs(packet->header.command) == ARV_GVCP_COMMAND_READ_REGISTER_ACK)
                    {
                        GInetAddress *interface_address =
                            g_inet_socket_address_get_address(G_INET_SOCKET_ADDRESS(socket->interface_address));
						// 使用 g_object_ref 函数增加 interface_address 的引用计数，以确保其持续有效。
                        g_object_ref(interface_address);
                        arv_gv_discover_socket_list_free(socket_list);
                        return interface_address;
                    }
                }
            } while (count > 0);
        }
    } while (1);
    arv_gv_discover_socket_list_free(socket_list);
    return NULL;
}

static ArvDevice *_open_device(ArvInterface *interface, GHashTable *devices, const char *device_id, GError **error)
{
    ArvGvInterface *gv_interface;
    ArvDevice *device = NULL;
    ArvGvInterfaceDeviceInfos *device_infos;
    GInetAddress *device_address;

    gv_interface = ARV_GV_INTERFACE(interface);
	// 查询 device_id 的设备信息
    if (device_id == NULL)
    {
        GList *device_list;

        device_list = g_hash_table_get_values(devices);
        device_infos = device_list != NULL ? device_list->data : NULL;
        g_list_free(device_list);
    }
    else
        device_infos = g_hash_table_lookup(devices, device_id);

    if (device_infos == NULL)
    {
        struct addrinfo hints;
        struct addrinfo *servinfo, *endpoint;

        if (device_id == NULL)
            return NULL;

        /* Try if device_id is a hostname/IP address */

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
		// 调用 getaddrinfo 函数，将 device_id 作为主机名或 IP 地址参数传递给它，并提供了设置好的 hints 结构体作为参数。在这里，端口号是 "3956"。
		// 如果 getaddrinfo 函数成功执行，它将为 device_id 获取到的网络地址信息填充到 servinfo 链表中，该链表包含一个或多个 addrinfo 结构体。
        if (getaddrinfo(device_id, "3956", &hints, &servinfo) != 0)
        {
            return NULL;
        }

        for (endpoint = servinfo; endpoint != NULL; endpoint = endpoint->ai_next)
        {
            char ipstr[INET_ADDRSTRLEN];
            struct sockaddr_in *ip = (struct sockaddr_in *)endpoint->ai_addr;

            inet_ntop(endpoint->ai_family, &ip->sin_addr, ipstr, sizeof(ipstr));
			// 得到设备地址
            device_address = g_inet_address_new_from_string(ipstr);
            if (device_address != NULL)
            {
                /* Try and find an interface that the camera will respond on */
                GInetAddress *interface_address = arv_gv_interface_camera_locate(gv_interface, device_address);

                if (interface_address != NULL)
                {
                    device = arv_gv_device_new(interface_address, device_address, NULL);
                    g_object_unref(interface_address);
                }
            }
            g_object_unref(device_address);
            if (device != NULL)
            {
                break;
            }
        }
        freeaddrinfo(servinfo);

        if (device == NULL)
            g_set_error(error, ARV_DEVICE_ERROR, ARV_DEVICE_ERROR_NOT_FOUND, "Can't connect to device at address '%s'", device_id);

        return device;
    }

    device_address = _device_infos_to_ginetaddress(device_infos);
    device = arv_gv_device_new(device_infos->interface_address, device_address, error);
    g_object_unref(device_address);

    return device;
}

static ArvDevice *arv_gv_interface_open_device(ArvInterface *interface, const char *device_id, GError **error)
{
    ArvDevice *device;
    ArvGvInterfaceDeviceInfos *device_infos;
    GError *local_error = NULL;
    int flags;

    device = _open_device(interface, ARV_GV_INTERFACE(interface)->priv->devices, device_id, &local_error);
    if (ARV_IS_DEVICE(device) || local_error != NULL)
    {
        if (local_error != NULL)
            g_propagate_error(error, local_error);
        return device;
    }

    flags = arv_interface_get_flags(interface);
    device_infos = _discover(NULL, device_id, flags & ARV_GVCP_DISCOVERY_PACKET_FLAGS_ALLOW_BROADCAST_ACK);
    if (device_infos != NULL)
    {
        GInetAddress *device_address;

        device_address = _device_infos_to_ginetaddress(device_infos);
        device = arv_gv_device_new(device_infos->interface_address, device_address, error);
        g_object_unref(device_address);

        arv_gv_interface_device_infos_unref(device_infos);

        return device;
    }

    return NULL;
}

static ArvInterface *arv_gv_interface = NULL;
static GMutex arv_gv_interface_mutex;

/**
 * arv_gv_interface_get_instance:
 *
 * Gets the unique instance of the GV interface.
 *
 * Returns: (transfer none): a #ArvInterface singleton.
 */
// 单例
ArvInterface *arv_gv_interface_get_instance(void)
{
    g_mutex_lock(&arv_gv_interface_mutex);

    if (arv_gv_interface == NULL)
        arv_gv_interface = g_object_new(ARV_TYPE_GV_INTERFACE, NULL);

    g_mutex_unlock(&arv_gv_interface_mutex);

    return ARV_INTERFACE(arv_gv_interface);
}

void arv_gv_interface_destroy_instance(void)
{
    g_mutex_lock(&arv_gv_interface_mutex);

    if (arv_gv_interface != NULL)
    {
        g_object_unref(arv_gv_interface);
        arv_gv_interface = NULL;
    }

    g_mutex_unlock(&arv_gv_interface_mutex);
}

static void arv_gv_interface_init(ArvGvInterface *gv_interface)
{
    gv_interface->priv = arv_gv_interface_get_instance_private(gv_interface);

    gv_interface->priv->devices = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, (GDestroyNotify)arv_gv_interface_device_infos_unref);
}

static void arv_gv_interface_finalize(GObject *object)
{
    ArvGvInterface *gv_interface = ARV_GV_INTERFACE(object);

    g_hash_table_unref(gv_interface->priv->devices);
    gv_interface->priv->devices = NULL;

    G_OBJECT_CLASS(arv_gv_interface_parent_class)->finalize(object);
}

static void arv_gv_interface_class_init(ArvGvInterfaceClass *gv_interface_class)
{
    GObjectClass *object_class = G_OBJECT_CLASS(gv_interface_class);
	// 获取父类指针
    ArvInterfaceClass *interface_class = ARV_INTERFACE_CLASS(gv_interface_class);

    object_class->finalize = arv_gv_interface_finalize;

    interface_class->update_device_list = arv_gv_interface_update_device_list;
    interface_class->open_device = arv_gv_interface_open_device;

    interface_class->protocol = "GigEVision";
}

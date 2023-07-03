/* echo-server.c - Networking echo server */

/*
 * Copyright (c) 2016 Intel Corporation.
 * Copyright (c) 2018 Nordic Semiconductor ASA.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(net_echo_server_sample, LOG_LEVEL_DBG);

#include <zephyr/kernel.h>
#include <zephyr/linker/sections.h>
#include <errno.h>
#include <zephyr/shell/shell.h>

#include <zephyr/net/net_core.h>
#include <zephyr/net/tls_credentials.h>

#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/net_event.h>
#include <zephyr/net/conn_mgr.h>

#include "common.h"
#include "certificate.h"

#define APP_BANNER "Run echo server"

static struct k_sem quit_lock;
static struct net_mgmt_event_callback mgmt_cb;
static bool connected;
K_SEM_DEFINE(run_app, 0, 1);
static bool want_to_quit;

#if defined(CONFIG_USERSPACE)
K_APPMEM_PARTITION_DEFINE(app_partition);
struct k_mem_domain app_domain;
#endif

#define EVENT_MASK (NET_EVENT_L4_CONNECTED | \
		    NET_EVENT_L4_DISCONNECTED)

APP_DMEM struct configs conf = {
	.ipv4 = {
		.proto = "IPv4",
	},
	.ipv6 = {
		.proto = "IPv6",
	},
};

void quit(void)
{
	k_sem_give(&quit_lock);
}

static void start_udp_and_tcp(void)
{
	LOG_INF("Starting...");

	if (IS_ENABLED(CONFIG_NET_TCP)) {
		start_tcp();
	}

	if (IS_ENABLED(CONFIG_NET_UDP)) {
		start_udp();
	}
}

static void stop_udp_and_tcp(void)
{
	LOG_INF("Stopping...");

	if (IS_ENABLED(CONFIG_NET_UDP)) {
		stop_udp();
	}

	if (IS_ENABLED(CONFIG_NET_TCP)) {
		stop_tcp();
	}
}

static void event_handler(struct net_mgmt_event_callback *cb,
			  uint32_t mgmt_event, struct net_if *iface)
{
	ARG_UNUSED(iface);
	ARG_UNUSED(cb);

	if ((mgmt_event & EVENT_MASK) != mgmt_event) {
		return;
	}

	if (want_to_quit) {
		k_sem_give(&run_app);
		want_to_quit = false;
	}

	if (mgmt_event == NET_EVENT_L4_CONNECTED) {
		LOG_INF("Network connected");

		connected = true;
		k_sem_give(&run_app);

		return;
	}

	if (mgmt_event == NET_EVENT_L4_DISCONNECTED) {
		if (connected == false) {
			LOG_INF("Waiting network to be connected");
		} else {
			LOG_INF("Network disconnected");
			connected = false;
		}

		k_sem_reset(&run_app);

		return;
	}
}

static void init_app(void)
{
#if defined(CONFIG_USERSPACE)
	struct k_mem_partition *parts[] = {
#if Z_LIBC_PARTITION_EXISTS
		&z_libc_partition,
#endif
		&app_partition
	};

	int ret = k_mem_domain_init(&app_domain, ARRAY_SIZE(parts), parts);

	__ASSERT(ret == 0, "k_mem_domain_init() failed %d", ret);
	ARG_UNUSED(ret);
#endif

#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS) || \
	defined(CONFIG_MBEDTLS_KEY_EXCHANGE_PSK_ENABLED)
	int err;
#endif

	k_sem_init(&quit_lock, 0, K_SEM_MAX_LIMIT);

	LOG_INF(APP_BANNER);

#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
#if defined(CONFIG_NET_SAMPLE_CERTS_WITH_SC)
	err = tls_credential_add(SERVER_CERTIFICATE_TAG,
				 TLS_CREDENTIAL_CA_CERTIFICATE,
				 ca_certificate,
				 sizeof(ca_certificate));
	if (err < 0) {
		LOG_ERR("Failed to register CA certificate: %d", err);
	}
#endif

	err = tls_credential_add(SERVER_CERTIFICATE_TAG,
				 TLS_CREDENTIAL_SERVER_CERTIFICATE,
				 server_certificate,
				 sizeof(server_certificate));
	if (err < 0) {
		LOG_ERR("Failed to register public certificate: %d", err);
	}


	err = tls_credential_add(SERVER_CERTIFICATE_TAG,
				 TLS_CREDENTIAL_PRIVATE_KEY,
				 private_key, sizeof(private_key));
	if (err < 0) {
		LOG_ERR("Failed to register private key: %d", err);
	}
#endif

#if defined(CONFIG_MBEDTLS_KEY_EXCHANGE_PSK_ENABLED)
	err = tls_credential_add(PSK_TAG,
				TLS_CREDENTIAL_PSK,
				psk,
				sizeof(psk));
	if (err < 0) {
		LOG_ERR("Failed to register PSK: %d", err);
	}
	err = tls_credential_add(PSK_TAG,
				TLS_CREDENTIAL_PSK_ID,
				psk_id,
				sizeof(psk_id) - 1);
	if (err < 0) {
		LOG_ERR("Failed to register PSK ID: %d", err);
	}
#endif

	if (IS_ENABLED(CONFIG_NET_CONNECTION_MANAGER)) {
		net_mgmt_init_event_callback(&mgmt_cb,
					     event_handler, EVENT_MASK);
		net_mgmt_add_event_callback(&mgmt_cb);

		conn_mgr_resend_status();
	}

	init_vlan();
	init_tunnel();

	init_usb();
}

static int cmd_sample_quit(const struct shell *sh,
			  size_t argc, char *argv[])
{
	want_to_quit = true;

	conn_mgr_resend_status();

	quit();

	return 0;
}

#ifdef CONFIG_NET_FILTER
#include <zephyr/net/net_filter.h>

enum ip_rule{
	any_ip,
	block_ip,
	allow_ip
};

static enum ip_rule current_rule = any_ip;
static struct in_addr ipv4_addr;

enum net_verdict ip_filter(struct net_pkt *pkt)
{
	enum net_verdict result = NET_CONTINUE;
	char addr[NET_IPV4_ADDR_LEN];
	struct in_addr *src_addr = (struct in_addr *)NET_IPV4_HDR(pkt)->src;

	printk("\n=========== %s ===========\n\n", __FUNCTION__);

	net_addr_ntop(AF_INET, src_addr, addr, NET_IPV4_ADDR_LEN);
	bool ip_match = net_ipv4_addr_cmp(src_addr, &ipv4_addr);

	if (ip_match && (current_rule == block_ip)) {
		/* Block just one IP address */
		result = NET_DROP;
	}
	else if(current_rule == allow_ip)
	{
		/* Unlock only one IP address */
		if(ip_match) {
			result = NET_CONTINUE;
		}
		else {
			result = NET_DROP;
		}
	}

	printk("IPv4 addr %s is %s\n", addr, (result == NET_CONTINUE) ? "passed" : "dropped");

	printk("\n=================================\n");
	return result;
}

enum net_verdict tcp_udp_filter(struct net_pkt *pkt)
{
	enum net_verdict result = NET_CONTINUE;
	uint8_t proto = (uint8_t)NET_IPV4_HDR(pkt)->proto;

	printk("\n=========== %s ===========\n\n", __FUNCTION__);

	if(proto == IPPROTO_TCP || proto == IPPROTO_UDP){
		result = NET_DROP;
	}
	else{
		printk("\n=================================\n");
		return NET_CONTINUE;
	}

	printk("%s is %s\n", (proto == IPPROTO_TCP) ? "TCP" : "UDP", (result == NET_CONTINUE) ? "passed" : "dropped");

	printk("\n=================================\n");
	return result;
}

#ifdef CONFIG_NET_IPV4
	struct nf_hook_cfg ipv4_cfg = {
		.hook_fn = ip_filter,
		.hooknum = NF_IP_PRE_ROUTING,
		.pf = PF_INET,
		.priority = -50,
	};

	struct nf_hook_cfg proto_cfg = {
		.hook_fn = tcp_udp_filter,
		.hooknum = NF_IP_LOCAL_IN,
		.pf = PF_INET,
		.priority = -50,
	};
#endif

static int cmd_sample_netfilter(const struct shell *sh,
			  size_t argc, char *argv[])
{
	if(argc > 1){
		if (!strcmp("ipv4", argv[1])) {
			if(argc > 2 && !strcmp("any", argv[2])){
				current_rule = any_ip;
				nf_unregister_net_hook(&ipv4_cfg);
				return 0;
			}

			if(argc > 3 && !strcmp("block", argv[2])) {
				if (net_addr_pton(AF_INET, argv[3], &ipv4_addr)) {
					printk("Invalid IP address: %s\n", argv[3]);
					return -EINVAL;
				}
				current_rule = block_ip;
				nf_unregister_net_hook(&ipv4_cfg);
				nf_register_net_hook(&ipv4_cfg);
				return 0;
			}
			else if(argc > 3 && !strcmp("allow", argv[2])) {
				if (net_addr_pton(AF_INET, argv[3], &ipv4_addr)) {
					printk("Invalid IP address: %s\n", argv[3]);
					return -EINVAL;
				}
				current_rule = allow_ip;
				nf_unregister_net_hook(&ipv4_cfg);
				nf_register_net_hook(&ipv4_cfg);
				return 0;
			}
		}
		else if(!strcmp("tcp_udp", argv[1])){
			if(argc > 2 && !strcmp("block", argv[2])){
				nf_register_net_hook(&proto_cfg);
				return 0;
			}
			else if(argc > 2 && !strcmp("allow", argv[2])){
				nf_unregister_net_hook(&proto_cfg);
				return 0;
			}

		}
	}

	printk("Invalid arguments\n");
	return -EINVAL;
}
#endif

SHELL_STATIC_SUBCMD_SET_CREATE(sample_commands,
	SHELL_CMD(quit, NULL,
		  "Quit the sample application\n",
		  cmd_sample_quit),
#ifdef CONFIG_NET_FILTER
	SHELL_CMD(net_filter, NULL,
		  "Setup net filter\n",
		  cmd_sample_netfilter),
#endif
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(sample, &sample_commands,
		   "Sample application commands", NULL);

int main(void)
{
	init_app();

	if (!IS_ENABLED(CONFIG_NET_CONNECTION_MANAGER)) {
		/* If the config library has not been configured to start the
		 * app only after we have a connection, then we can start
		 * it right away.
		 */
		k_sem_give(&run_app);
	}

	/* Wait for the connection. */
	k_sem_take(&run_app, K_FOREVER);

	start_udp_and_tcp();

	k_sem_take(&quit_lock, K_FOREVER);

	if (connected) {
		stop_udp_and_tcp();
	}
	return 0;
}

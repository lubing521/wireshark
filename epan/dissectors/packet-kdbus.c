/* packet-kdbus.c
 * Routines for kdbus packet disassembly
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 *
 * This file created by Daniel Mack <daniel@zonque.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>

#include <string.h>
#include <stdint.h>

#include <wiretap/wtap.h>
#include <epan/packet.h>
#include "packet-kdbus.h"
#include <epan/atalk-utils.h>
#include <epan/prefs.h>
#include "packet-ip.h"
#include "packet-ipv6.h"
#include "packet-ipx.h"
#include "packet-osi.h"
#include "packet-ppp.h"
#include <epan/etypes.h>
#include <epan/aftypes.h>

static dissector_table_t kdbus_dissector_table;

/* protocols and header fields */
static int proto_kdbus = -1;
static int proto_kdbus_item = -1;
static int hf_kdbus_msg_size = -1;
static int hf_kdbus_msg_flags = -1;
static int hf_kdbus_msg_priority = -1;
static int hf_kdbus_msg_dst_id = -1;
static int hf_kdbus_msg_src_id = -1;
static int hf_kdbus_msg_payload_type = -1;
static int hf_kdbus_msg_cookie = -1;
static int hf_kdbus_msg_cookie_reply = -1;
static int hf_kdbus_msg_timeout_ns = -1;
static int hf_kdbus_msg_flag_expect_reply = -1;
static int hf_kdbus_msg_flag_sync_reply = -1;
static int hf_kdbus_msg_flag_no_auto_start = -1;

static int hf_kdbus_item_size = -1;
static int hf_kdbus_item_type = -1;
static int hf_kdbus_item_string = -1;
static int hf_kdbus_item_memfd_size = -1;
static int hf_kdbus_item_memfd_fd = -1;
static int hf_kdbus_item_timestamp_monotonic = -1;
static int hf_kdbus_item_timestamp_realtime = -1;
static int hf_kdbus_item_vec_size = -1;
static int hf_kdbus_item_vec_address = -1;
static int hf_kdbus_item_vec_offset = -1;
static int hf_kdbus_item_vec_payload = -1;
static int hf_kdbus_item_creds_uid = -1;
static int hf_kdbus_item_creds_gid = -1;
static int hf_kdbus_item_creds_pid = -1;
static int hf_kdbus_item_creds_tid = -1;
static int hf_kdbus_item_creds_starttime = -1;
static int hf_kdbus_item_caps_inheritable = -1;
static int hf_kdbus_item_caps_permitted = -1;
static int hf_kdbus_item_caps_effective = -1;
static int hf_kdbus_item_caps_bset = -1;
static int hf_kdbus_item_bloom = -1;
static int hf_kdbus_item_audit_sessionid = -1;
static int hf_kdbus_item_audit_loginuid = -1;

static int hf_kdbus_name_flag_replace_existing = -1;
static int hf_kdbus_name_flag_allow_replacement = -1;
static int hf_kdbus_name_flag_queue = -1;
static int hf_kdbus_name_flag_in_queue = -1;
static int hf_kdbus_name_flag_activator = -1;

static int hf_kdbus_item_cap_chown;
static int hf_kdbus_item_cap_dac_override;
static int hf_kdbus_item_cap_read_search;
static int hf_kdbus_item_cap_fowner;
static int hf_kdbus_item_cap_fsetid;
static int hf_kdbus_item_cap_kill;
static int hf_kdbus_item_cap_setgid;
static int hf_kdbus_item_cap_setuid;
static int hf_kdbus_item_cap_setpcap;
static int hf_kdbus_item_cap_linux_immutable;
static int hf_kdbus_item_cap_bind_service;
static int hf_kdbus_item_cap_net_broadcast;
static int hf_kdbus_item_cap_net_admin;
static int hf_kdbus_item_cap_net_raw;
static int hf_kdbus_item_cap_ipc_clock;
static int hf_kdbus_item_cap_ipc_owner;
static int hf_kdbus_item_cap_sys_module;
static int hf_kdbus_item_cap_sys_rawio;
static int hf_kdbus_item_cap_sys_chroot;
static int hf_kdbus_item_cap_sys_ptrace;
static int hf_kdbus_item_cap_sys_pacct;
static int hf_kdbus_item_cap_sys_admin;
static int hf_kdbus_item_cap_sys_boot;
static int hf_kdbus_item_cap_sys_nice;
static int hf_kdbus_item_cap_sys_resource;
static int hf_kdbus_item_cap_sys_time;
static int hf_kdbus_item_cap_sys_tty_config;
static int hf_kdbus_item_cap_mknod;
static int hf_kdbus_item_cap_lease;
static int hf_kdbus_item_cap_audit_write;
static int hf_kdbus_item_cap_audit_control;
static int hf_kdbus_item_cap_setfcap;
static int hf_kdbus_item_cap_mac_override;
static int hf_kdbus_item_cap_admin;
static int hf_kdbus_item_cap_syslog;
static int hf_kdbus_item_cap_wake_alarm;
static int hf_kdbus_item_cap_block_suspend;



static gint ett_kdbus = -1;
static gint ett_kdbus_item = -1;

static dissector_handle_t item_handle;

static const val64_string payload_types[] = {
	{ KDBUS_PAYLOAD_KERNEL,		"Kernel" },
	{ KDBUS_PAYLOAD_DBUS,		"DBusDBus" },
};

static const val64_string item_types[] = {
	{ _KDBUS_ITEM_NULL,		"NULL" },

	/* Filled in by userspace */
	{ KDBUS_ITEM_PAYLOAD_VEC,	"data_vec, reference to memory area" },
	{ KDBUS_ITEM_PAYLOAD_OFF,	"data_vec, reference to memory area" },
	{ KDBUS_ITEM_PAYLOAD_MEMFD,	"file descriptor of a special data file" },
	{ KDBUS_ITEM_FDS,		"file descriptor(s)" },
	{ KDBUS_ITEM_BLOOM_PARAMETER,	"bloom filter parameter" },
	{ KDBUS_ITEM_BLOOM_FILTER,	"bloom filter filter" },
	{ KDBUS_ITEM_BLOOM_MASK,	"bloom filter mask" },
	{ KDBUS_ITEM_DST_NAME,		"destination's well-known name" },

	{ KDBUS_ITEM_NAME,		"name" },
	{ KDBUS_ITEM_CONN_NAME,		"connection name" },
	{ KDBUS_ITEM_TIMESTAMP,		"timestamp" },
	{ KDBUS_ITEM_CREDS,		"creds" },
	{ KDBUS_ITEM_PID_COMM,		"pid comm" },
	{ KDBUS_ITEM_TID_COMM,		"tid comm" },
	{ KDBUS_ITEM_EXE,		"src exe" },
	{ KDBUS_ITEM_CMDLINE,		"cmdline" },
	{ KDBUS_ITEM_CGROUP,		"cgroup" },
	{ KDBUS_ITEM_CAPS,		"caps" },
	{ KDBUS_ITEM_SECLABEL,		"seclabel" },
	{ KDBUS_ITEM_AUDIT,		"audit" },

	{ KDBUS_ITEM_NAME_ADD,		"name add" },
	{ KDBUS_ITEM_NAME_REMOVE,	"name remove" },
	{ KDBUS_ITEM_NAME_CHANGE,	"name change" },
	{ KDBUS_ITEM_ID_ADD,		"id add" },
	{ KDBUS_ITEM_ID_REMOVE,		"id remove" },
	{ KDBUS_ITEM_REPLY_TIMEOUT,	"reply timeout" },
	{ KDBUS_ITEM_REPLY_DEAD,	"reply dead" },
};

static hf_register_info hf_msg[] = {
	{ &hf_kdbus_msg_size,
		{ "Message size", "msg.size", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_msg_flags,
		{ "Flags", "msg.flags", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_msg_priority,
		{ "Priority", "msg.priority", FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_msg_dst_id,
		{ "Destination ID", "msg.dst_id", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_msg_src_id,
		{ "Source ID", "msg.src_id", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_msg_cookie,
		{ "Cookie", "msg.cookie", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_msg_cookie_reply,
		{ "Cookie reply", "msg.cookie_reply", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_msg_timeout_ns,
		{ "Timeout (ns)", "msg.timeout_ns", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_msg_payload_type,
		{ "Payload type", "msg.payload_type", FT_UINT64, BASE_HEX | BASE_VAL64_STRING, VALS(payload_types), 0x0, NULL, HFILL }},

	/* message flags */
	{ &hf_kdbus_msg_flag_expect_reply,
		{ "Expect reply", "msg.flags.expect_reply", FT_BOOLEAN, 8, NULL, KDBUS_MSG_FLAGS_EXPECT_REPLY, NULL, HFILL }},
	{ &hf_kdbus_msg_flag_sync_reply,
		{ "Sync reply", "msg.flags.sync_reply", FT_BOOLEAN, 8, NULL, KDBUS_MSG_FLAGS_SYNC_REPLY, NULL, HFILL }},
	{ &hf_kdbus_msg_flag_no_auto_start,
		{ "No auto start", "msg.flags.no_auto_start", FT_BOOLEAN, 8, NULL, KDBUS_MSG_FLAGS_NO_AUTO_START, NULL, HFILL }},
};

static hf_register_info hf_item[] = {
	{ &hf_kdbus_item_size,
		{ "Size", "item.size", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_type,
		{ "Type", ".item.type", FT_UINT64, BASE_HEX | BASE_VAL64_STRING, VALS(item_types), 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_string,
		{ "String value", "item.string", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_memfd_size,
		{ "memfd size", "item.memfd.size", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_memfd_fd,
		{ "memfd fd", "item.memfd.fd", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_timestamp_monotonic,
		{ "Timestamp (monotonic)", "item.timestamp.monotonic_ns", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_timestamp_realtime, { "Timestamp (realtime)", ".item.timestamp.realtime_ns", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_vec_size,
		{ "Data vector size", "item.vec.size", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_vec_address,
		{ "Data vector address", "item.vec.address", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_vec_offset,
		{ "Data vector offset", "item.vec.offset", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_vec_payload,
		{ "Data vector payload", "item.vec.payload", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_bloom,
		{ "Bloom filter data", "item.bloom", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_audit_sessionid,
		{ "Audit session ID", "item.audit.sessionid", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_audit_loginuid,
		{ "Audit login UID", "item.audit.loginuid", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},

	{ &hf_kdbus_name_flag_replace_existing,
		{ "Replace existing", "name.flags.replace_existing", FT_BOOLEAN, 8, NULL, KDBUS_NAME_REPLACE_EXISTING, NULL, HFILL }},
	{ &hf_kdbus_name_flag_allow_replacement,
		{ "Allow replacement", "name.flags.allow_replacement", FT_BOOLEAN, 8, NULL, KDBUS_NAME_ALLOW_REPLACEMENT, NULL, HFILL }},
	{ &hf_kdbus_name_flag_queue,
		{ "Queue", "name.flags.queue", FT_BOOLEAN, 8, NULL, KDBUS_NAME_QUEUE, NULL, HFILL }},
	{ &hf_kdbus_name_flag_in_queue,
		{ "In queue", "name.flags.in_queue", FT_BOOLEAN, 8, NULL, KDBUS_NAME_IN_QUEUE, NULL, HFILL }},
	{ &hf_kdbus_name_flag_activator,
		{ "Activator", "name.flags.activator", FT_BOOLEAN, 8, NULL, KDBUS_NAME_ACTIVATOR, NULL, HFILL }},

	{ &hf_kdbus_item_creds_uid,
		{ "Creds UID", "item.creds.uid", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_creds_gid,
		{ "Creds GID", "item.creds.gid", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_creds_pid,
		{ "Creds PID", "item.creds.pid", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_creds_tid,
		{ "Creds TID", "item.creds.tid", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_creds_starttime,
		{ "Creds start time", "item.creds.starttime", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},

	{ &hf_kdbus_item_caps_inheritable,
		{ "Caps (inheritable)", "item.caps.inheritable", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_caps_permitted,
		{ "Caps (permitted)", "item.caps.permitted", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_caps_effective,
		{ "Caps (effective)", "item.caps.effective", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_caps_bset,
		{ "Caps (bset)", "item.caps.bset", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

	/* caps u32.0 */
	{ &hf_kdbus_item_cap_chown,
		{ "chown", "item.cap.chown", FT_BOOLEAN, 8, NULL, 1 << 0, NULL, HFILL }},
	{ &hf_kdbus_item_cap_dac_override,
		{ "DAC override", "item.cap.dac_override", FT_BOOLEAN, 8, NULL, 1 << 1, NULL, HFILL }},
	{ &hf_kdbus_item_cap_read_search,
		{ "DAC read search", "item.cap.dac_read_search", FT_BOOLEAN, 8, NULL, 1 << 2, NULL, HFILL }},
	{ &hf_kdbus_item_cap_fowner,
		{ "fowner", "item.cap.fowner", FT_BOOLEAN, 8, NULL, 1 << 3, NULL, HFILL }},
	{ &hf_kdbus_item_cap_fsetid,
		{ "fsetid", "item.cap.fsetid", FT_BOOLEAN, 8, NULL, 1 << 4, NULL, HFILL }},
	{ &hf_kdbus_item_cap_kill,
		{ "kill", "item.cap.kill", FT_BOOLEAN, 8, NULL, 1 << 5, NULL, HFILL }},
	{ &hf_kdbus_item_cap_setgid,
		{ "setgid", "item.cap.setgid", FT_BOOLEAN, 8, NULL, 1 << 6, NULL, HFILL }},
	{ &hf_kdbus_item_cap_setuid,
		{ "setuid", "item.cap.setuid", FT_BOOLEAN, 8, NULL, 1 << 7, NULL, HFILL }},
	{ &hf_kdbus_item_cap_setpcap,
		{ "setpcap", "item.cap.setpcap", FT_BOOLEAN, 8, NULL, 1 << 8, NULL, HFILL }},
	{ &hf_kdbus_item_cap_linux_immutable,
		{ "linux immutable", "item.cap.linux_immuntable", FT_BOOLEAN, 8, NULL, 1 << 9, NULL, HFILL }},
	{ &hf_kdbus_item_cap_bind_service,
		{ "bind service", "item.cap.bind_service", FT_BOOLEAN, 8, NULL, 1 << 10, NULL, HFILL }},
	{ &hf_kdbus_item_cap_net_broadcast,
		{ "net broadcast", "item.cap.net_broadcast", FT_BOOLEAN, 8, NULL, 1 << 11, NULL, HFILL }},
	{ &hf_kdbus_item_cap_net_admin,
		{ "net admin", "item.cap.net_admin", FT_BOOLEAN, 8, NULL, 1 << 12, NULL, HFILL }},
	{ &hf_kdbus_item_cap_net_raw,
		{ "net raw", "item.cap.net_raw", FT_BOOLEAN, 8, NULL, 1 << 13, NULL, HFILL }},
	{ &hf_kdbus_item_cap_ipc_clock,
		{ "ipc clock", "item.cap.ipc_clock", FT_BOOLEAN, 8, NULL, 1 << 14, NULL, HFILL }},
	{ &hf_kdbus_item_cap_ipc_owner,
		{ "ipc owner", "item.cap.ipc_owner", FT_BOOLEAN, 8, NULL, 1 << 15, NULL, HFILL }},
	{ &hf_kdbus_item_cap_sys_module,
		{ "sys module", "item.cap.sys_module", FT_BOOLEAN, 8, NULL, 1 << 16, NULL, HFILL }},
	{ &hf_kdbus_item_cap_sys_rawio,
		{ "sys raw i/o", "item.cap.sys_rawio", FT_BOOLEAN, 8, NULL, 1 << 17, NULL, HFILL }},
	{ &hf_kdbus_item_cap_sys_chroot,
		{ "sys chroot", "item.cap.sys_chroot", FT_BOOLEAN, 8, NULL, 1 << 18, NULL, HFILL }},
	{ &hf_kdbus_item_cap_sys_ptrace,
		{ "sys ptrace", "item.cap.sys_ptrace", FT_BOOLEAN, 8, NULL, 1 << 19, NULL, HFILL }},
	{ &hf_kdbus_item_cap_sys_pacct,
		{ "sys pacct", "item.cap.sys_pacct", FT_BOOLEAN, 8, NULL, 1 << 20, NULL, HFILL }},
	{ &hf_kdbus_item_cap_sys_admin,
		{ "sys admin", "item.cap.sys_admin", FT_BOOLEAN, 8, NULL, 1 << 21, NULL, HFILL }},
	{ &hf_kdbus_item_cap_sys_boot,
		{ "sys boot", "item.cap.sys_boot", FT_BOOLEAN, 8, NULL, 1 << 22, NULL, HFILL }},
	{ &hf_kdbus_item_cap_sys_nice,
		{ "sys nice", "item.cap.sys_nice", FT_BOOLEAN, 8, NULL, 1 << 23, NULL, HFILL }},
	{ &hf_kdbus_item_cap_sys_resource,
		{ "sys resource", "item.cap.sys_resource", FT_BOOLEAN, 8, NULL, 1 << 24, NULL, HFILL }},
	{ &hf_kdbus_item_cap_sys_time,
		{ "sys time", "item.cap.sys_time", FT_BOOLEAN, 8, NULL, 1 << 25, NULL, HFILL }},
	{ &hf_kdbus_item_cap_sys_tty_config,
		{ "sys tty config", "item.cap.sys_tty_config", FT_BOOLEAN, 8, NULL, 1 << 26, NULL, HFILL }},
	{ &hf_kdbus_item_cap_mknod,
		{ "sys mknod", "item.cap.mknod", FT_BOOLEAN, 8, NULL, 1 << 27, NULL, HFILL }},
	{ &hf_kdbus_item_cap_lease,
		{ "lease", "item.cap.lease", FT_BOOLEAN, 8, NULL, 1 << 28, NULL, HFILL }},
	{ &hf_kdbus_item_cap_audit_write,
		{ "audit write", "item.cap.audit_write", FT_BOOLEAN, 8, NULL, 1 << 29, NULL, HFILL }},
	{ &hf_kdbus_item_cap_audit_control,
		{ "audit control", "item.cap.audit_control", FT_BOOLEAN, 8, NULL, 1 << 30, NULL, HFILL }},
	{ &hf_kdbus_item_cap_setfcap,
		{ "setfcap", "item.cap.setfcap", FT_BOOLEAN, 8, NULL, 1 << 31, NULL, HFILL }},

	/* caps u32.1 */
	{ &hf_kdbus_item_cap_mac_override,
		{ "MAC override", "item.cap.mac_override", FT_BOOLEAN, 8, NULL, 1 << 0, NULL, HFILL }},
	{ &hf_kdbus_item_cap_admin,
		{ "admin", "item.cap.admin", FT_BOOLEAN, 8, NULL, 1 << 1, NULL, HFILL }},
	{ &hf_kdbus_item_cap_syslog,
		{ "syslog", "item.cap.syslog", FT_BOOLEAN, 8, NULL, 1 << 2, NULL, HFILL }},
	{ &hf_kdbus_item_cap_wake_alarm,
		{ "wake alarm", "item.cap.wake_alarm", FT_BOOLEAN, 8, NULL, 1 << 3, NULL, HFILL }},
	{ &hf_kdbus_item_cap_block_suspend,
		{ "block suspend", "item.cap.block_suspend", FT_BOOLEAN, 8, NULL, 1 << 4, NULL, HFILL }},
};

static gint *ett[] = {
	&ett_kdbus,
	&ett_kdbus_item,
};


/* Family values. */
static const value_string family_vals[] = {
	{ 0,	NULL },
};

#if 0
void
capture_kdbus(const guchar *pd, int len, packet_counts *ld)
{

}
#endif

static void
dissect_item(tvbuff_t *msg_tvb, tvbuff_t *tvb, proto_tree *tree)
{
	struct kdbus_item *item;
	uint64_t size;

	tvb_memcpy(tvb, &size, 0, sizeof(size));
	item = (struct kdbus_item *) tvb_memdup(wmem_packet_scope(), tvb, 0, size);

	proto_tree_add_uint64(tree, hf_kdbus_item_size, tvb,
			      offsetof(struct kdbus_item, size), sizeof(uint64_t),
			      item->size);
	proto_tree_add_uint64(tree, hf_kdbus_item_type, tvb,
			      offsetof(struct kdbus_item, type), sizeof(uint64_t),
			      item->type);

	switch (item->type) {
	case _KDBUS_ITEM_NULL:
		break;
	case KDBUS_ITEM_PAYLOAD_VEC:
		proto_tree_add_uint64(tree, hf_kdbus_item_vec_size, tvb,
				      offsetof(struct kdbus_item, vec.size),
				      sizeof(uint64_t), item->vec.size);
		proto_tree_add_uint64(tree, hf_kdbus_item_vec_address, tvb,
				      offsetof(struct kdbus_item, vec.address),
				      sizeof(uint64_t), item->vec.address);
		break;
	case KDBUS_ITEM_PAYLOAD_OFF:
		proto_tree_add_uint64(tree, hf_kdbus_item_vec_size, tvb,
				      offsetof(struct kdbus_item, vec.size),
				      sizeof(uint64_t), item->vec.size);
		proto_tree_add_uint64(tree, hf_kdbus_item_vec_offset, tvb,
				      offsetof(struct kdbus_item, vec.offset),
				      sizeof(uint64_t), item->vec.offset);
		proto_tree_add_bytes(tree, hf_kdbus_item_vec_payload, msg_tvb,
				     item->vec.offset, item->vec.size,
				     tvb_get_ptr(msg_tvb, item->vec.offset, item->vec.size));
		break;
	case KDBUS_ITEM_PAYLOAD_MEMFD:
		proto_tree_add_uint64(tree, hf_kdbus_item_memfd_size, tvb,
				      offsetof(struct kdbus_item, memfd.size),
				      sizeof(uint64_t), item->memfd.size);
		proto_tree_add_uint(tree, hf_kdbus_item_memfd_fd, tvb,
				    offsetof(struct kdbus_item, memfd.fd),
				    sizeof(int), item->memfd.fd);
		break;
	case KDBUS_ITEM_FDS:
		break;
	case KDBUS_ITEM_BLOOM_MASK:
		proto_tree_add_bytes(tree, hf_kdbus_item_bloom, tvb,
				     0, 64 /* FIXME */, item->data);
		break;
	case KDBUS_ITEM_DST_NAME:
	case KDBUS_ITEM_NAME: {
		int flags_off = offsetof(struct kdbus_item, name) + offsetof(struct kdbus_name, flags);

		proto_tree_add_uint64(tree, hf_kdbus_msg_flags, tvb,
				      flags_off, sizeof(item->name.flags), item->name.flags);
		proto_tree_add_item(tree, hf_kdbus_name_flag_replace_existing, tvb,
				    flags_off, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_kdbus_name_flag_allow_replacement, tvb,
				    flags_off, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_kdbus_name_flag_queue, tvb,
				    flags_off, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_kdbus_name_flag_in_queue, tvb,
				    flags_off, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_kdbus_name_flag_activator, tvb,
				    flags_off, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_string(tree, hf_kdbus_item_string, tvb,
				      offsetof(struct kdbus_item, name) + offsetof(struct kdbus_name, name),
				      size - offsetof(struct kdbus_item, name) - offsetof(struct kdbus_name, name),
				      item->name.name);
		break;
	}

	case KDBUS_ITEM_TIMESTAMP:
		proto_tree_add_uint64(tree, hf_kdbus_item_timestamp_monotonic, tvb,
				      offsetof(struct kdbus_item, timestamp.monotonic_ns),
				      sizeof(uint64_t), item->timestamp.monotonic_ns);
		proto_tree_add_uint64(tree, hf_kdbus_item_timestamp_realtime, tvb,
				      offsetof(struct kdbus_item, timestamp.realtime_ns),
				      sizeof(uint64_t), item->timestamp.realtime_ns);
		break;
	case KDBUS_ITEM_CREDS:
		proto_tree_add_uint64(tree, hf_kdbus_item_creds_uid, tvb,
				      offsetof(struct kdbus_item, creds.uid),
				      sizeof(uint64_t), item->creds.uid);
		proto_tree_add_uint64(tree, hf_kdbus_item_creds_gid, tvb,
				      offsetof(struct kdbus_item, creds.gid),
				      sizeof(uint64_t), item->creds.gid);
		proto_tree_add_uint64(tree, hf_kdbus_item_creds_pid, tvb,
				      offsetof(struct kdbus_item, creds.pid),
				      sizeof(uint64_t), item->creds.pid);
		proto_tree_add_uint64(tree, hf_kdbus_item_creds_tid, tvb,
				      offsetof(struct kdbus_item, creds.tid),
				      sizeof(uint64_t), item->creds.tid);
		proto_tree_add_uint64(tree, hf_kdbus_item_creds_starttime, tvb,
				      offsetof(struct kdbus_item, creds.starttime),
				      sizeof(uint64_t), item->creds.starttime);
		break;
	case KDBUS_ITEM_AUDIT:
		proto_tree_add_uint64(tree, hf_kdbus_item_audit_sessionid, tvb,
				      offsetof(struct kdbus_item, audit.sessionid),
				      sizeof(uint64_t), item->audit.sessionid);
		proto_tree_add_uint64(tree, hf_kdbus_item_audit_loginuid, tvb,
				      offsetof(struct kdbus_item, audit.loginuid),
				      sizeof(uint64_t), item->audit.loginuid);
		break;
	case KDBUS_ITEM_CAPS: {
		unsigned int i;
		int hfindex[] = {
			hf_kdbus_item_caps_inheritable,
			hf_kdbus_item_caps_permitted,
			hf_kdbus_item_caps_effective,
			hf_kdbus_item_caps_bset,
		};

		for (i = 0; i < G_N_ELEMENTS(hfindex); i++)
			proto_tree_add_bytes(tree, hfindex[i], tvb,
					     offsetof(struct kdbus_item, data) + (KDBUS_CAP_SIZE * i),
					     KDBUS_CAP_SIZE, item->data + (KDBUS_CAP_SIZE * i));

		break;
	}
	case KDBUS_ITEM_PID_COMM:
	case KDBUS_ITEM_TID_COMM:
	case KDBUS_ITEM_EXE:
	case KDBUS_ITEM_CMDLINE:
	case KDBUS_ITEM_CGROUP:
	case KDBUS_ITEM_SECLABEL:
	case KDBUS_ITEM_CONN_NAME:
	case KDBUS_ITEM_NAME_ADD:
	case KDBUS_ITEM_NAME_REMOVE:
	case KDBUS_ITEM_NAME_CHANGE:
	case KDBUS_ITEM_ID_ADD:
	case KDBUS_ITEM_ID_REMOVE:
		proto_tree_add_string(tree, hf_kdbus_item_string, tvb,
				      offsetof(struct kdbus_item, str),
				      size - offsetof(struct kdbus_item, str),
				      item->str);
		break;
	case KDBUS_ITEM_REPLY_TIMEOUT:
		break;
	case KDBUS_ITEM_REPLY_DEAD:
		break;
	}
}

static void
dissect_kdbus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	char *tmp;
	const char *payload_type;
	struct kdbus_msg msg;
	uint64_t offset;

	tvb_memcpy(tvb, &msg, 0, sizeof(msg));

	tmp = wmem_strdup_printf(wmem_file_scope(), "connection #%llu", (unsigned long long) msg.src_id);
	col_set_str(pinfo->cinfo, COL_RES_DL_SRC, tmp);

	tmp = wmem_strdup_printf(wmem_file_scope(), "connection #%llu", (unsigned long long) msg.dst_id);
	col_set_str(pinfo->cinfo, COL_RES_DL_DST, tmp);

	payload_type = val_to_str(msg.payload_type,
				  (const value_string *) payload_types,
				  "Unknown (0x%zx)");
	col_set_str(pinfo->cinfo, COL_PROTOCOL, payload_type);
	col_set_str(pinfo->cinfo, COL_INFO, "kdbus message");

	proto_tree_add_uint64(tree, hf_kdbus_msg_size, tvb,
			offsetof(struct kdbus_msg, size),
			sizeof(msg.size), msg.size);
	proto_tree_add_int64(tree, hf_kdbus_msg_priority, tvb,
			offsetof(struct kdbus_msg, priority),
			sizeof(msg.priority), msg.priority);
	proto_tree_add_uint64(tree, hf_kdbus_msg_flags, tvb,
			offsetof(struct kdbus_msg, flags),
			sizeof(msg.flags), msg.flags);

	proto_tree_add_item(tree, hf_kdbus_msg_flag_expect_reply, tvb,
			    offsetof(struct kdbus_msg, flags),
			    1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_kdbus_msg_flag_sync_reply, tvb,
			    offsetof(struct kdbus_msg, flags),
			    1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_kdbus_msg_flag_no_auto_start, tvb,
			    offsetof(struct kdbus_msg, flags),
			    1, ENC_LITTLE_ENDIAN);

	proto_tree_add_uint64(tree, hf_kdbus_msg_src_id, tvb,
			offsetof(struct kdbus_msg, src_id),
			sizeof(msg.src_id), msg.src_id);
	proto_tree_add_uint64(tree, hf_kdbus_msg_dst_id, tvb,
			offsetof(struct kdbus_msg, dst_id),
			sizeof(msg.dst_id), msg.dst_id);
	proto_tree_add_uint64(tree, hf_kdbus_msg_payload_type, tvb,
			offsetof(struct kdbus_msg, payload_type),
			sizeof(msg.payload_type), msg.payload_type);
	proto_tree_add_uint64(tree, hf_kdbus_msg_cookie, tvb,
			offsetof(struct kdbus_msg, cookie),
			sizeof(msg.cookie), msg.cookie);

	if (msg.flags & KDBUS_ITEM_REPLY_TIMEOUT)
		proto_tree_add_uint64(tree, hf_kdbus_msg_cookie_reply, tvb,
					offsetof(struct kdbus_msg, cookie_reply),
					sizeof(msg.cookie_reply), msg.cookie_reply);
	else
		proto_tree_add_uint64(tree, hf_kdbus_msg_timeout_ns, tvb,
					offsetof(struct kdbus_msg, timeout_ns),
					sizeof(msg.timeout_ns), msg.timeout_ns);

	offset = offsetof(struct kdbus_msg, items);
	msg.size -= offset;

	while (msg.size > 0) {
		proto_tree *subtree;
		proto_item *item;
		tvbuff_t *subtvb;
		uint64_t size;
		KDBUS_PART_HEADER hdr;

		tvb_memcpy(tvb, &hdr, offset, sizeof(hdr));
		size = KDBUS_ALIGN8(hdr.size);
		subtvb = tvb_new_subset_length(tvb, offset, size);

		item = proto_tree_add_item(tree, proto_kdbus_item, tvb,
					   offset, size, ENC_NA);

		proto_item_append_text(item, ", Type '%s'",
				       val_to_str(hdr.type, (const value_string *) item_types,
				       		  "Unknown (0x%zx)"));
		subtree = proto_item_add_subtree(item, ett_kdbus_item);

		dissect_item(tvb, subtvb, subtree);

		offset += size;
		msg.size -= size;
	}
}

void
proto_register_kdbus(void)
{
	proto_kdbus = proto_register_protocol("kernel dbus", "kdbus", "kdbus");
	proto_register_field_array(proto_kdbus, hf_msg, array_length(hf_msg));
	proto_register_subtree_array(ett, array_length(ett));

	/* subdissector code */
	kdbus_dissector_table =
		register_dissector_table("kdbus.item", "kdbus item type",
					 FT_UINT32, BASE_HEX);

	proto_kdbus_item = proto_register_protocol("kdbus message item", "item", "item");
	proto_register_field_array(proto_kdbus_item, hf_item, array_length(hf_item));
}

void
proto_reg_handoff_kdbus(void)
{
	dissector_handle_t kdbus_handle;

	item_handle = find_dissector("item");
	kdbus_handle = create_dissector_handle(dissect_kdbus, proto_kdbus);
	dissector_add_uint("wtap_encap", WTAP_ENCAP_KDBUS, kdbus_handle);
}

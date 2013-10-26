/* packet-kdbus.h
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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

#ifndef __PACKET_KDBUS_H__
#define __PACKET_KDBUS_H__


/* FIXME: the following definitions should eventually live somewhere else */
/* ---------------------------------------- 8< ------------------------------------ */

#define KDBUS_IOC_MAGIC			0x95
#define KDBUS_SRC_ID_KERNEL		(0)
#define KDBUS_DST_ID_NAME		(0)
#define KDBUS_MATCH_ID_ANY		(~0ULL)
#define KDBUS_DST_ID_BROADCAST		(~0ULL)

/**
 * struct kdbus_notify_id_change - name registry change message
 * @id:			New or former owner of the name
 * @flags:		flags field from KDBUS_HELLO_*
 *
 * Sent from kernel to userspace when the owner or activator of
 * a well-known name changes.
 *
 * Attached to:
 *   KDBUS_ITEM_ID_ADD
 *   KDBUS_ITEM_ID_REMOVE
 */
struct kdbus_notify_id_change {
	uint64_t id;
	uint64_t flags;
};

/**
 * struct kdbus_notify_name_change - name registry change message
 * @old:		ID and flags of former owner of a name
 * @new:		ID and flags of new owner of a name
 * @name:		Well-known name
 *
 * Sent from kernel to userspace when the owner or activator of
 * a well-known name changes.
 *
 * Attached to:
 *   KDBUS_ITEM_NAME_ADD
 *   KDBUS_ITEM_NAME_REMOVE
 *   KDBUS_ITEM_NAME_CHANGE
 */
struct kdbus_notify_name_change {
	struct kdbus_notify_id_change old;
	struct kdbus_notify_id_change _new;
	char name[0];
};

/**
 * struct kdbus_creds - process credentials
 * @uid:		User ID
 * @gid:		Group ID
 * @pid:		Process ID
 * @tid:		Thread ID
 * @starttime:		Starttime of the process
 *
 * The starttime of the process PID. This is useful to detect PID overruns
 * from the client side. i.e. if you use the PID to look something up in
 * /proc/$PID/ you can afterwards check the starttime field of it, to ensure
 * you didn't run into a PID overrun.
 *
 * Attached to:
 *   KDBUS_ITEM_CREDS
 */
struct kdbus_creds {
	uint64_t uid;
	uint64_t gid;
	uint64_t pid;
	uint64_t tid;
	uint64_t starttime;
};

/**
 * struct kdbus_audit - audit information
 * @sessionid:		The audit session ID
 * @loginuid:		The audit login uid
 *
 * Attached to:
 *   KDBUS_ITEM_AUDIT
 */
struct kdbus_audit {
	uint64_t sessionid;
	uint64_t loginuid;
};

/**
 * struct kdbus_timestamp
 * @seqnum:		Global per-namespace message sequence number
 * @monotonic_ns:	Monotonic timestamp, in nanoseconds
 * @realtime_ns:	Realtime timestamp, in nanoseconds
 *
 * Attached to:
 *   KDBUS_ITEM_TIMESTAMP
 */
struct kdbus_timestamp {
	uint64_t seqnum;
	uint64_t monotonic_ns;
	uint64_t realtime_ns;
};

/**
 * struct kdbus_vec - I/O vector for kdbus payload items
 * @size:		The size of the vector
 * @address:		Memory address for memory addresses
 * @offset:		Offset in the in-message payload memory,
 *			relative to the message head
 *
 * Attached to:
 *   KDBUS_ITEM_PAYLOAD_VEC
 */
struct kdbus_vec {
	uint64_t size;
	union {
		uint64_t address;
		uint64_t offset;
	};
};

/**
 * struct kdbus_memfd - a kdbus memfd
 * @size:		The memfd's size
 * @fd:			The file descriptor number
 * @__pad:		Padding to ensure proper alignement and size
 *
 * Attached to:
 *   KDBUS_ITEM_PAYLOAD_MEMFD
 */
struct kdbus_memfd {
	uint64_t size;
	int fd;
	uint32_t __pad;
};

/**
 * struct kdbus_name - a registered well-known name with its flags
 * @flags:		flags from KDBUS_NAME_*
 * @name:		well-known name
 *
 * Attached to:
 *   KDBUS_ITEM_NAME
 */
struct kdbus_name {
	uint64_t flags;
	char name[0];
};

/**
 * struct kdbus_policy_access - policy access item
 * @type:		One of KDBUS_POLICY_ACCESS_* types
 * @bits:		Access to grant. One of KDBUS_POLICY_*
 * @id:			For KDBUS_POLICY_ACCESS_USER, the uid
 *			For KDBUS_POLICY_ACCESS_GROUP, the gid
 *
 * Embedded in:
 *   struct kdbus_policy
 */
struct kdbus_policy_access {
	uint64_t type;	/* USER, GROUP, WORLD */
	uint64_t bits;	/* RECV, SEND, OWN */
	uint64_t id;	/* uid, gid, 0 */
};

/**
 * struct kdbus_policy - a policy item
 * @access:		Policy access details
 * @name:		Well-known name to grant access to
 *
 * Attached to:
 *   KDBUS_POLICY_ACCESS
 *   KDBUS_ITEM_POLICY_NAME
 */
struct kdbus_policy {
	union {
		struct kdbus_policy_access access;
		char name[0];
	};
};

/**
 * enum kdbus_item_type - item types to chain data in a list
 * @_KDBUS_ITEM_NULL:		Uninitialized/invalid
 * @_KDBUS_ITEM_USER_BASE:	Start of user items
 * @KDBUS_ITEM_PAYLOAD_VEC:	Vector to data
 * @KDBUS_ITEM_PAYLOAD_OFF:	Data at returned offset to message head
 * @KDBUS_ITEM_PAYLOAD_MEMFD:	Data as sealed memfd
 * @KDBUS_ITEM_FDS:		Attached file descriptors
 * @KDBUS_ITEM_BLOOM_PARAMETER:	Bus-wide bloom parameters, used with
 *				KDBUS_CMD_BUS_MAKE, carries a
 *				struct kdbus_bloom_parameter
 * @KDBUS_ITEM_BLOOM_FILTER:	Bloom filter carried with a message, used to
 *				match against a bloom mask of a connection,
 *				carries a struct kdbus_bloom_filter
 * @KDBUS_ITEM_BLOOM_MASK:	Bloom mask used to match against a message's
 *				bloom filter
 * @KDBUS_ITEM_DST_NAME:	Destination's well-known name
 * @KDBUS_ITEM_MAKE_NAME:	Name of domain, bus, endpoint
 * @KDBUS_ITEM_MEMFD_NAME:	The human readable name of a memfd (debugging)
 * @KDBUS_ITEM_ATTACH_FLAGS:	Attach-flags, used for updating which metadata
 *				a connection subscribes to
 * @_KDBUS_ITEM_ATTACH_BASE:	Start of metadata attach items
 * @KDBUS_ITEM_NAME:		Well-know name with flags
 * @KDBUS_ITEM_ID:		Connection ID
 * @KDBUS_ITEM_TIMESTAMP:	Timestamp
 * @KDBUS_ITEM_CREDS:		Process credential
 * @KDBUS_ITEM_PID_COMM:	Process ID "comm" identifier
 * @KDBUS_ITEM_TID_COMM:	Thread ID "comm" identifier
 * @KDBUS_ITEM_EXE:		The path of the executable
 * @KDBUS_ITEM_CMDLINE:		The process command line
 * @KDBUS_ITEM_CGROUP:		The croup membership
 * @KDBUS_ITEM_CAPS:		The process capabilities
 * @KDBUS_ITEM_SECLABEL:	The security label
 * @KDBUS_ITEM_AUDIT:		The audit IDs
 * @KDBUS_ITEM_CONN_NAME:	The connection's human-readable name (debugging)
 * @_KDBUS_ITEM_POLICY_BASE:	Start of policy items
 * @KDBUS_ITEM_POLICY_NAME:	Policy in struct kdbus_policy
 * @KDBUS_ITEM_POLICY_ACCESS:	Policy in struct kdbus_policy
 * @_KDBUS_ITEM_KERNEL_BASE:	Start of kernel-generated message items
 * @KDBUS_ITEM_NAME_ADD:	Notify in struct kdbus_notify_name_change
 * @KDBUS_ITEM_NAME_REMOVE:	Notify in struct kdbus_notify_name_change
 * @KDBUS_ITEM_NAME_CHANGE:	Notify in struct kdbus_notify_name_change
 * @KDBUS_ITEM_ID_ADD:		Notify in struct kdbus_notify_id_change
 * @KDBUS_ITEM_ID_REMOVE:	Notify in struct kdbus_notify_id_change
 * @KDBUS_ITEM_REPLY_TIMEOUT:	Timeout has been reached
 * @KDBUS_ITEM_REPLY_DEAD:	Destination died
 */
enum kdbus_item_type {
	_KDBUS_ITEM_NULL,
	_KDBUS_ITEM_USER_BASE,
	KDBUS_ITEM_PAYLOAD_VEC	= _KDBUS_ITEM_USER_BASE,
	KDBUS_ITEM_PAYLOAD_OFF,
	KDBUS_ITEM_PAYLOAD_MEMFD,
	KDBUS_ITEM_FDS,
	KDBUS_ITEM_BLOOM_PARAMETER,
	KDBUS_ITEM_BLOOM_FILTER,
	KDBUS_ITEM_BLOOM_MASK,
	KDBUS_ITEM_DST_NAME,
	KDBUS_ITEM_MAKE_NAME,
	KDBUS_ITEM_MEMFD_NAME,
	KDBUS_ITEM_ATTACH_FLAGS,

	_KDBUS_ITEM_ATTACH_BASE	= 0x1000,
	KDBUS_ITEM_NAME		= _KDBUS_ITEM_ATTACH_BASE,
	KDBUS_ITEM_ID,
	KDBUS_ITEM_TIMESTAMP,
	KDBUS_ITEM_CREDS,
	KDBUS_ITEM_PID_COMM,
	KDBUS_ITEM_TID_COMM,
	KDBUS_ITEM_EXE,
	KDBUS_ITEM_CMDLINE,
	KDBUS_ITEM_CGROUP,
	KDBUS_ITEM_CAPS,
	KDBUS_ITEM_SECLABEL,
	KDBUS_ITEM_AUDIT,
	KDBUS_ITEM_CONN_NAME,

	_KDBUS_ITEM_POLICY_BASE	= 0x2000,
	KDBUS_ITEM_POLICY_NAME = _KDBUS_ITEM_POLICY_BASE,
	KDBUS_ITEM_POLICY_ACCESS,

	_KDBUS_ITEM_KERNEL_BASE	= 0x8000,
	KDBUS_ITEM_NAME_ADD	= _KDBUS_ITEM_KERNEL_BASE,
	KDBUS_ITEM_NAME_REMOVE,
	KDBUS_ITEM_NAME_CHANGE,
	KDBUS_ITEM_ID_ADD,
	KDBUS_ITEM_ID_REMOVE,
	KDBUS_ITEM_REPLY_TIMEOUT,
	KDBUS_ITEM_REPLY_DEAD,
};

/**
 * struct kdbus_item - chain of data blocks
 * @size:		Overall data record size
 * @type:		Kdbus_item type of data
 * @data:		Generic bytes
 * @data32:		Generic 32 bit array
 * @data64:		Generic 64 bit array
 * @str:		Generic string
 * @id:			Connection ID
 * @vec:		KDBUS_ITEM_PAYLOAD_VEC
 * @creds:		KDBUS_ITEM_CREDS
 * @audit:		KDBUS_ITEM_AUDIT
 * @timestamp:		KDBUS_ITEM_TIMESTAMP
 * @name:		KDBUS_ITEM_NAME
 * @memfd:		KDBUS_ITEM_PAYLOAD_MEMFD
 * @name_change:	KDBUS_ITEM_NAME_ADD
 *			KDBUS_ITEM_NAME_REMOVE
 *			KDBUS_ITEM_NAME_CHANGE
 * @id_change:		KDBUS_ITEM_ID_ADD
 *			KDBUS_ITEM_ID_REMOVE
 * @policy:		KDBUS_ITEM_POLICY_NAME
 *			KDBUS_ITEM_POLICY_ACCESS
 */
struct kdbus_item {
	uint64_t size;
	uint64_t type;
	union {
		uint8_t data[0];
		uint32_t data32[0];
		uint64_t data64[0];
		char str[0];

		uint64_t id;
		struct kdbus_vec vec;
		struct kdbus_creds creds;
		struct kdbus_audit audit;
		struct kdbus_timestamp timestamp;
		struct kdbus_name name;
		struct kdbus_memfd memfd;
		int fds[0];
		struct kdbus_notify_name_change name_change;
		struct kdbus_notify_id_change id_change;
		struct kdbus_policy policy;
	};
};

/**
 * enum kdbus_msg_flags - type of message
 * @KDBUS_MSG_FLAGS_EXPECT_REPLY:	Expect a reply message, used for
 *					method calls. The userspace-supplied
 *					cookie identifies the message and the
 *					respective reply carries the cookie
 *					in cookie_reply
 * @KDBUS_MSG_FLAGS_SYNC_REPLY:		Wait for destination connection to
 * 					reply to this message. The
 * 					KDBUS_CMD_MSG_SEND ioctl() will block
 * 					until the reply is received, and
 * 					offset_reply in struct kdbus_msg will
 * 					yield the offset in the sender's pool
 * 					where the reply can be found.
 * 					This flag is only valid if
 * 					@KDBUS_MSG_FLAGS_EXPECT_REPLY is set as
 * 					well.
 * @KDBUS_MSG_FLAGS_NO_AUTO_START:	Do not start a service, if the addressed
 *					name is not currently active
 */
enum kdbus_msg_flags {
	KDBUS_MSG_FLAGS_EXPECT_REPLY	= 1 << 0,
	KDBUS_MSG_FLAGS_SYNC_REPLY	= 1 << 1,
	KDBUS_MSG_FLAGS_NO_AUTO_START	= 1 << 2,
};

/**
 * enum kdbus_payload_type - type of payload carried by message
 * @KDBUS_PAYLOAD_KERNEL:	Kernel-generated simple message
 * @KDBUS_PAYLOAD_DBUS:		D-Bus marshalling "DBusDBus"
 */
enum kdbus_payload_type {
	KDBUS_PAYLOAD_KERNEL,
	KDBUS_PAYLOAD_DBUS	= 0x4442757344427573ULL,
};

/**
 * struct kdbus_msg - the representation of a kdbus message
 * @size:		Total size of the message
 * @flags:		Message flags (KDBUS_MSG_FLAGS_*)
 * @priority:		Message queue priority value
 * @dst_id:		64-bit ID of the destination connection
 * @src_id:		64-bit ID of the source connection
 * @payload_type:	Payload type (KDBUS_PAYLOAD_*)
 * @cookie:		Userspace-supplied cookie, for the connection
 *			to identify its messages
 * @timeout_ns:		The time to wait for a message reply from the peer.
 *			If there is no reply, a kernel-generated message
 *			with an attached KDBUS_ITEM_REPLY_TIMEOUT item
 *			is sent to @src_id.
 * @cookie_reply:	A reply to the requesting message with the same
 *			cookie. The requesting connection can match its
 *			request and the reply with this value
 * @offset_reply:	If KDBUS_MSG_FLAGS_WAIT_FOR_REPLY, this field will
 *			contain the offset in the sender's pool where the
 *			reply is stored.
 * @items:		A list of kdbus_items containing the message payload
 */
struct kdbus_msg {
	uint64_t size;
	uint64_t flags;
	int64_t priority;
	uint64_t dst_id;
	uint64_t src_id;
	uint64_t payload_type;
	uint64_t cookie;
	union {
		uint64_t timeout_ns;
		uint64_t cookie_reply;
		uint64_t offset_reply;
	};
	struct kdbus_item items[0];
} __attribute__((aligned(8)));

/**
 * enum kdbus_name_flags - properties of a well-known name
 * @KDBUS_NAME_REPLACE_EXISTING:	Try to replace name of other connections
 * @KDBUS_NAME_ALLOW_REPLACEMENT:	Allow the replacement of the name
 * @KDBUS_NAME_QUEUE:			Name should be queued if busy
 * @KDBUS_NAME_IN_QUEUE:		Name is queued
 * @KDBUS_NAME_ACTIVATOR:		Name is owned by a activator connection
 */
enum kdbus_name_flags {
	KDBUS_NAME_REPLACE_EXISTING	= 1 <<  0,
	KDBUS_NAME_ALLOW_REPLACEMENT	= 1 <<  1,
	KDBUS_NAME_QUEUE		= 1 <<  2,
	KDBUS_NAME_IN_QUEUE		= 1 <<  3,
	KDBUS_NAME_ACTIVATOR		= 1 <<  4,
};

/* Common first elements in a structure which are used to iterate over
 * a list of elements. */
#define KDBUS_PART_HEADER \
	struct {                                                        \
		uint64_t size;                                          \
		uint64_t type;                                          \
	}

#define KDBUS_CAP_SIZE (2 * 4)
#define KDBUS_PART_HEADER_SIZE 16
#define KDBUS_ALIGN8(l) (((l) + 7) & ~7)
#define KDBUS_ITEM_SIZE(s) KDBUS_ALIGN8((s) + KDBUS_PART_HEADER_SIZE)

/* ---------------------------------------- 8< ------------------------------------ */


#include "ws_symbol_export.h"

WS_DLL_PUBLIC
void capture_kdbus(const guchar *, int, packet_counts *);

#endif

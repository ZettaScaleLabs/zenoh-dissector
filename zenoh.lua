--
-- Copyright (c) 2021 Carlos Guimarães
--
-- This program and the accompanying materials are made available under the
-- terms of the Eclipse Public License 2.0 which is available at
-- http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
-- which is available at https://www.apache.org/licenses/LICENSE-2.0.
--
-- SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
--
-- Contributors:
--   Carlos Guimarães, <carlos.em.guimaraes@gmail.com>
--   Luca Cominardi, <luca.cominardi@gmail.com>
--   Angelo Corsaro, <angelo@icorsaro.net>
--

--- DISSECTOR INFO & FIELDS ---
local proto_zenoh_tcp = Proto("zenoh-tcp", "Zenoh Protocol over TCP")
local proto_zenoh_udp = Proto("zenoh-udp", "Zenoh Protocol over UDP")
local proto_zenoh = Proto("zenoh", "Zenoh Protocol")

-- Zenoh TCP
proto_zenoh_tcp.fields.len = ProtoField.uint16("zenoh.len", "Len", base.u16)

-- Zenoh Header
proto_zenoh.fields.header_msgid = ProtoField.uint8("zenoh.msgid", "MsgId", base.HEX)

-- Declare Message Specific
proto_zenoh.fields.declare_flags              = ProtoField.uint8("zenoh.declare.flags", "Flags", base.HEX)
proto_zenoh.fields.declare_num_of_declaration = ProtoField.uint8("zenoh.declare.number", "Number of Declarations", base.u8)

-- Data Message Specific
proto_zenoh.fields.data_flags = ProtoField.uint8("zenoh.data.flags", "Flags", base.HEX)

-- Pull Message Specific
proto_zenoh.fields.pull_flags      = ProtoField.uint8("zenoh.pull.flags", "Flags", base.HEX)
proto_zenoh.fields.pull_pullid     = ProtoField.uint8("zenoh.pull.pullid", "Pull ID", base.u8)
proto_zenoh.fields.pull_maxsamples = ProtoField.uint8("zenoh.pull.maxsamples", "Max Samples", base.u8)

-- Unit Message Specific
proto_zenoh.fields.unit_flags = ProtoField.uint8("zenoh.unit.flags", "Flags", base.HEX)

-- Link State List Message Specific
proto_zenoh.fields.linkstatelist_flags = ProtoField.uint8("zenoh.linkstatelist.flags", "Flags", base.HEX)
proto_zenoh.fields.linkstatelist_size  = ProtoField.uint8("zenoh.linkstatelist.number", "Number of Link States", base.u8)

-- Query Message Specific
proto_zenoh.fields.query_flags     = ProtoField.uint8("zenoh.query.flags", "Flags", base.HEX)
proto_zenoh.fields.query_predicate = ProtoField.bytes("zenoh.query.predicate", "Predicate", base.NONE)
proto_zenoh.fields.query_qid       = ProtoField.uint8("zenoh.query.qid", "Query ID", base.u8)

-- Init Message Specific
proto_zenoh.fields.init_flags        = ProtoField.uint8("zenoh.init.flags", "Flags", base.HEX)
proto_zenoh.fields.init_option_flags = ProtoField.uint8("zenoh.init.option_flags", "Option Flags", base.HEX)
proto_zenoh.fields.init_vmaj         = ProtoField.uint8("zenoh.init.v_maj", "VMaj", base.u8)
proto_zenoh.fields.init_vmin         = ProtoField.uint8("zenoh.init.v_min", "VMin", base.u8)
proto_zenoh.fields.init_whatami      = ProtoField.uint8("zenoh.init.whatami", "WhatAmI", base.u8)
proto_zenoh.fields.init_peerid       = ProtoField.bytes("zenoh.init.peer_id", "Peer ID", base.NONE)
proto_zenoh.fields.init_snresolution = ProtoField.uint8("zenoh.init.sn_resolution", "SN Resolution", base.u8)
proto_zenoh.fields.init_cookie       = ProtoField.bytes("zenoh.init.cookie", "Cookie", base.NONE)

-- Open Message Specific
proto_zenoh.fields.open_flags     = ProtoField.uint8("zenoh.open.flags", "Flags", base.HEX)
proto_zenoh.fields.open_lease     = ProtoField.uint8("zenoh.open.lease", "Lease Period", base.u8)
proto_zenoh.fields.open_initialsn = ProtoField.uint8("zenoh.open.initial_sn", "Initial SN", base.u8)
proto_zenoh.fields.open_cookie    = ProtoField.bytes("zenoh.open.cookie", "Cookie", base.NONE)

-- Close Message Specific
proto_zenoh.fields.close_flags  = ProtoField.uint8("zenoh.close.flags", "Flags", base.HEX)
proto_zenoh.fields.close_peerid = ProtoField.bytes("zenoh.close.peerid", "Peer ID", base.NONE)
proto_zenoh.fields.close_reason = ProtoField.uint8("zenoh.close.reason", "Reason", base.u8)

-- Sync Message Specific
proto_zenoh.fields.sync_flags = ProtoField.uint8("zenoh.sync.flags", "Flags", base.HEX)
proto_zenoh.fields.sync_sn    = ProtoField.uint8("zenoh.sync.sn", "SN", base.u8)
proto_zenoh.fields.sync_count = ProtoField.uint8("zenoh.sync.count", "Count", base.u8)

-- AckNack Message Specific
proto_zenoh.fields.acknack_flags = ProtoField.uint8("zenoh.acknack.flags", "Flags", base.HEX)
proto_zenoh.fields.acknack_sn    = ProtoField.uint8("zenoh.acknack.sn", "SN", base.u8)
proto_zenoh.fields.acknack_mask  = ProtoField.uint8("zenoh.acknack.mask", "Mask", base.u8)

-- Join Message Specific
proto_zenoh.fields.join_flags        = ProtoField.uint8("zenoh.join.flags", "Flags", base.HEX)
proto_zenoh.fields.join_option_flags = ProtoField.uint8("zenoh.join.option_flags", "Option Flags", base.HEX)
proto_zenoh.fields.join_vmaj         = ProtoField.uint8("zenoh.join.v_maj", "VMaj", base.u8)
proto_zenoh.fields.join_vmin         = ProtoField.uint8("zenoh.join.v_min", "VMin", base.u8)
proto_zenoh.fields.join_whatami      = ProtoField.uint8("zenoh.join.whatami", "WhatAmI", base.u8)
proto_zenoh.fields.join_peerid       = ProtoField.bytes("zenoh.join.peer_id", "Peer ID", base.NONE)
proto_zenoh.fields.join_lease        = ProtoField.bytes("zenoh.join.lease", "Lease", base.u8)
proto_zenoh.fields.join_snresolution = ProtoField.uint8("zenoh.join.sn_resolution", "SN Resolution", base.u8)

-- Scout Message Specific
proto_zenoh.fields.scout_flags   = ProtoField.uint8("zenoh.scout.flags", "Flags", base.HEX)
proto_zenoh.fields.scout_version = ProtoField.uint8("zenoh.scout.version", "Version", base.u8)
proto_zenoh.fields.scout_what    = ProtoField.uint8("zenoh.scout.what", "What", base.u8)
proto_zenoh.fields.scout_zenohid = ProtoField.bytes("zenoh.scout.zid", "Zenoh ID", base.NONE)

-- Hello Message Specific
proto_zenoh.fields.hello_flags   = ProtoField.uint8("zenoh.hello.flags", "Flags", base.HEX)
proto_zenoh.fields.hello_peerid  = ProtoField.bytes("zenoh.hello.peerid", "Peer ID", base.NONE)
proto_zenoh.fields.hello_whatami = ProtoField.uint8("zenoh.hello.whatami", "WhatAmI", base.u8)

-- Keep Alive Message Specific
proto_zenoh.fields.keepalive_flags  = ProtoField.uint8("zenoh.keepalive.flags", "Flags", base.HEX)
proto_zenoh.fields.keepalive_peerid = ProtoField.bytes("zenoh.keepalive.peerid", "Peer ID", base.NONE)

-- Ping Pong Message Specific
proto_zenoh.fields.pingpong_flags = ProtoField.uint8("zenoh.pingpong.flags", "Flags", base.HEX)
proto_zenoh.fields.pingpong_hash  = ProtoField.bytes("zenoh.pingpong.hash", "Hash", base.NONE)

-- Frame Message Specific
proto_zenoh.fields.frame_flags   = ProtoField.uint8("zenoh.frame.flags", "Flags", base.HEX)
proto_zenoh.fields.frame_sn      = ProtoField.uint8("zenoh.frame.sn", "SN", base.u8)
proto_zenoh.fields.frame_payload = ProtoField.uint8("zenoh.frame.payload", "Payload", base.u8)

-- Priority Decorator Specific
-- TODO: add ID field

-- Attachment Decorator Specific
proto_zenoh.fields.attachment_flags = ProtoField.uint8("zenoh.attachment.flags", "Flags", base.HEX)

-- Routing Context Decorator Specific
proto_zenoh.fields.routingcontext_flags = ProtoField.uint8("zenoh.routingcontext.flags", "Flags", base.HEX)
proto_zenoh.fields.routingcontext_tid   = ProtoField.uint8("zenoh.routingcontext.tid", "TID", base.u8)

-- Reply Context Decorator Specific
proto_zenoh.fields.replycontext_flags       = ProtoField.uint8("zenoh.replycontext.flags", "Flags", base.HEX)
proto_zenoh.fields.replycontext_qid         = ProtoField.uint8("zenoh.replycontext.qid", "QID", base.u8)
proto_zenoh.fields.replycontext_replierkind = ProtoField.uint8("zenoh.replycontext.replier_kind", "Source Kind", base.u8)
proto_zenoh.fields.replycontext_replierid   = ProtoField.bytes("zenoh.replycontext.replier_id", "Replier ID", base.NONE)


---------- CONSTANTS ----------
function protect(tbl)
  return setmetatable({}, {
    __index = tbl,
    __newindex = function(t, key, value)
      error("attempting to change constant " ..
      tostring(key) .. " to " .. tostring(value), 2)
    end
  })
end

-- Zenoh Message Types
ZENOH_MSGID = {
  DECLARE         = 0x0b,
  DATA            = 0x0c,
  QUERY           = 0x0d,
  PULL            = 0x0e,
  UNIT            = 0x0f,
  LINK_STATE_LIST = 0x10
}
ZENOH_MSGID = protect(ZENOH_MSGID)

-- Session Message Types
SESSION_MSGID = {
  JOIN       = 0x00,
  SCOUT      = 0x01,
  HELLO      = 0x02,
  INIT       = 0x03,
  OPEN       = 0x04,
  CLOSE      = 0x05,
  SYNC       = 0x06,
  ACK_NACK   = 0x07,
  KEEP_ALIVE = 0x08,
  PING_PONG  = 0x09,
  FRAME      = 0x0a
}
SESSION_MSGID = protect(SESSION_MSGID)

-- Decorators Message Types
DECORATORS_MSGID = {
  PRIORITY        = 0x1c,
  ROUTING_CONTEXT = 0x1d,
  REPLY_CONTEXT   = 0x1e,
  ATTACHMENT      = 0x1f
}
DECORATORS_MSGID = protect(DECORATORS_MSGID)

-- Declaration Type Identifiers
DECLARATION_ID = {
  RESOURCE          = 0x01,
  PUBLISHER         = 0x02,
  SUBSCRIBER        = 0x03,
  QUERYABLE         = 0x04,
  FORGET_RESOURCE   = 0x11,
  FORGET_PUBLISHER  = 0x12,
  FORGET_SUBSCRIBER = 0x13,
  FORGET_QUERYABLE  = 0x14
}
DECLARATION_ID = protect(DECLARATION_ID)

PRIORITY_NUM = 8

------ Global Variables -----
local pending_fragments = {}

----------- Flags -----------
-- DECLARE Flags
function get_declare_flag_description(flag)
  local f_description = "Unknown"

  if flag == 0x04 then f_description     = "Unused" -- X
  elseif flag == 0x02 then f_description = "Unused" -- X
  elseif flag == 0x01 then f_description = "Unused" -- X
  end

  return f_description
end

function get_declare_resource_flag_description(flag)
  local f_description = "Unknown"

  if flag == 0x04 then f_description     = "ResourceKey" -- K
  elseif flag == 0x02 then f_description = "Unused"      -- X
  elseif flag == 0x01 then f_description = "Unused"      -- X
  end

  return f_description
end

function get_declare_publisher_flag_description(flag)
  local f_description = "Unknown"

  if flag == 0x04 then f_description     = "ResourceKey" -- K
  elseif flag == 0x02 then f_description = "Unused"      -- X
  elseif flag == 0x01 then f_description = "Unused"      -- X
  end

  return f_description
end

function get_declare_subscriber_flag_description(flag)
  local f_description = "Unknown"

  if flag == 0x04 then f_description     = "ResourceKey" -- K
  elseif flag == 0x02 then f_description = "SubMode"     -- S
  elseif flag == 0x01 then f_description = "Reliable"    -- R
  end

  return f_description
end

function get_declare_queryable_flag_description(flag)
  local f_description = "Unknown"

  if flag == 0x04 then f_description     = "ResourceKey"   -- K
  elseif flag == 0x02 then f_description = "QueryableKind" -- Q
  elseif flag == 0x01 then f_description = "Unused"        -- X
  end

  return f_description
end

function get_forget_resource_flag_description(flag)
  local f_description = "Unknown"

  if flag == 0x04 then f_description     = "Unused" -- X
  elseif flag == 0x02 then f_description = "Unused" -- X
  elseif flag == 0x01 then f_description = "Unused" -- X
  end

  return f_description
end

function get_forget_publisher_flag_description(flag)
  local f_description = "Unknown"

  if flag == 0x04 then f_description     = "ResourceKey" -- K
  elseif flag == 0x02 then f_description = "Unused"      -- X
  elseif flag == 0x01 then f_description = "Unused"      -- X
  end

  return f_description
end

function get_forget_subscriber_flag_description(flag)
  local f_description = "Unknown"

  if flag == 0x04 then f_description     = "ResourceKey" -- K
  elseif flag == 0x02 then f_description = "Unused"      -- X
  elseif flag == 0x01 then f_description = "Unused"      -- X
  end

  return f_description
end

function get_forget_queryable_flag_description(flag)
  local f_description = "Unknown"

  if flag == 0x04 then f_description     = "ResourceKey" -- K
  elseif flag == 0x02 then f_description = "Unused"      -- X
  elseif flag == 0x01 then f_description = "Unused"      -- X
  end

  return f_description
end

-- Data flags
function get_data_flag_description(flag)
  local f_description = "Unknown"

  if flag == 0x04 then f_description     = "ResourceKey" -- K
  elseif flag == 0x02 then f_description = "DataInfo"    -- I
  elseif flag == 0x01 then f_description = "Dropping"    -- D
  end

  return f_description
end

function get_options_flag_description(flag)
  local f_description = "Unknown"

  if flag == 0x01 then f_description = "QoS" -- Q
  end

  return f_description
end

function get_data_options_flag_description(flag)
  local f_description = "Unknown"

  if flag == 0x00 then f_description     = "Payload is sliced"
  elseif flag == 0x01 then f_description = "Payload kind"
  elseif flag == bit.lshift(0x01, 1) then f_description = "Payload encoding"
  elseif flag == bit.lshift(0x01, 2) then f_description = "Payload timestamp"
  elseif flag == bit.lshift(0x01, 7) then f_description = "Payload source ID"
  elseif flag == bit.lshift(0x01, 8) then f_description = "Payload source SN"
  elseif flag == bit.lshift(0x01, 9) then f_description = "First router ID"
  elseif flag == bit.lshift(0x01, 10) then f_description = "First router SN"
  elseif flag > bit.lshift(0x01, 63) then f_description = "Unknown"
  else f_description = "Reserved"
  end

  return f_description
end

-- Pull flags
function get_pull_flag_description(flag)
  local f_description = "Unknown"

  if flag == 0x04 then f_description     = "ResourceKey" -- K
  elseif flag == 0x02 then f_description = "MaxSamples"  -- N
  elseif flag == 0x01 then f_description = "Final"       -- F
  end

  return f_description
end

-- Unit flags
function get_unit_flag_description(flag)
  local f_description = "Unknown"

  if flag == 0x04 then f_description     = "Unused"   -- X
  elseif flag == 0x02 then f_description = "Unused"   -- X
  elseif flag == 0x01 then f_description = "Dropping" -- D
  end

  return f_description
end

-- Link State flags
function get_link_state_flag_description(flag)
  local f_description = "Unknown"

  if flag == 0x80 then f_description     = "Unused"     -- X
  elseif flag == 0x40 then f_description = "Unused"     -- X
  elseif flag == 0x20 then f_description = "Unused"     -- X
  elseif flag == 0x10 then f_description = "Unused"     -- X
  elseif flag == 0x08 then f_description = "Unused"     -- X
  elseif flag == 0x04 then f_description = "Locators"   -- L
  elseif flag == 0x02 then f_description = "WhatAmI"    -- W
  elseif flag == 0x01 then f_description = "PingOrPong" -- P
  end

  return f_description
end

-- Link State List flags
function get_linkstatelist_flag_description(flag)
  local f_description = "Unknown"

  if flag == 0x04 then f_description     = "Unused" -- X
  elseif flag == 0x02 then f_description = "Unused" -- X
  elseif flag == 0x01 then f_description = "Unused" -- X
  end

  return f_description
end

-- Query flags
function get_query_flag_description(flag)
  local f_description = "Unknown"

  if flag == 0x04 then f_description     = "ResourceKey" -- K
  elseif flag == 0x02 then f_description = "Unused"      -- X
  elseif flag == 0x01 then f_description = "QueryTarget" -- T
  end

  return f_description
end

-- Init flags
function get_init_flag_description(flag)
  local f_description = "Unknown"

  if flag == 0x04 then f_description     = "Options"       -- O
  elseif flag == 0x02 then f_description = "SN Resolution" -- S
  elseif flag == 0x01 then f_description = "Ack"           -- A
  end

  return f_description
end

-- Open flags
function get_open_flag_description(flag)
  local f_description = "Unknown"

  if flag == 0x04 then f_description     = "Unused"  -- X
  elseif flag == 0x02 then f_description = "TimeRes" -- T
  elseif flag == 0x01 then f_description = "Ack"     -- A
  end

  return f_description
end

-- Close flags
function get_close_flag_description(flag)
  local f_description = "Unknown"

  if flag == 0x04 then f_description     = "Unused"    -- X
  elseif flag == 0x02 then f_description = "CloseLink" -- K
  elseif flag == 0x01 then f_description = "PeerID"    -- I
  end

  return f_description
end

-- Sync flags
function get_sync_flag_description(flag)
  local f_description = "Unknown"

  if flag == 0x04 then f_description     = "Unused"   -- X
  elseif flag == 0x02 then f_description = "Count"    -- C
  elseif flag == 0x01 then f_description = "Reliable" -- R
  end

  return f_description
end

-- AckNack flags
function get_acknack_flag_description(flag)
  local f_description = "Unknown"

  if flag == 0x04 then f_description     = "Unused" -- X
  elseif flag == 0x02 then f_description = "Unused" -- X
  elseif flag == 0x01 then f_description = "Mask"   -- M
  end

  return f_description
end

-- Join flags
function get_join_flag_description(flag)
  local f_description = "Unknown"

  if flag == 0x04 then f_description     = "Options"       -- O
  elseif flag == 0x02 then f_description = "SN Resolution" -- S
  elseif flag == 0x01 then f_description = "TimeRes"       -- U
  end

  return f_description
end

-- Scout flags
function get_scout_flag_description(flag)
  local f_description = "Unknown"

  if flag == 0x04 then f_description     = "Zenoh Extensions" -- Z
  elseif flag == 0x02 then f_description = "Unused"           -- X
  elseif flag == 0x01 then f_description = "ZenohID"          -- I
  end

  return f_description
end

-- Hello flags
function get_hello_flag_description(flag)
  local f_description = "Unknown"

  if flag == 0x04 then f_description     = "Locators" -- L
  elseif flag == 0x02 then f_description = "WhatAmI"  -- W
  elseif flag == 0x01 then f_description = "PeerID"   -- I
  end

  return f_description
end

-- PingPong flags
function get_pingpong_flag_description(flag)
  local f_description = "Unknown"

  if flag == 0x04 then f_description     = "Unused"     -- X
  elseif flag == 0x02 then f_description = "Unused"     -- X
  elseif flag == 0x01 then f_description = "PingOrPong" -- P
  end

  return f_description
end

-- Keep Alive flags
function get_keepalive_flag_description(flag)
  local f_description = "Unknown"

  if flag == 0x04 then f_description     = "Unused" -- X
  elseif flag == 0x02 then f_description = "Unused" -- X
  elseif flag == 0x01 then f_description = "PeerID" -- I
  end

  return f_description
end

-- Frame flags
function get_frame_flag_description(flag)
  local f_description = "Unknown"

  if flag == 0x04 then f_description     = "End"      -- E
  elseif flag == 0x02 then f_description = "Fragment" -- F
  elseif flag == 0x01 then f_description = "Reliable" -- R
  end

  return f_description
end

-- Routing Context flags
function get_routingcontext_flag_description(flag)
  local f_description = "Unknown"

  if flag == 0x04 then f_description     = "Unused" -- X
  elseif flag == 0x02 then f_description = "Unused" -- X
  elseif flag == 0x01 then f_description = "Unused" -- X
  end

  return f_description
end

-- Reply Context flags
function get_replycontext_flag_description(flag)
  local f_description = "Unknown"

  if flag == 0x04 then f_description     = "Unused" -- X
  elseif flag == 0x02 then f_description = "Unused" -- X
  elseif flag == 0x01 then f_description = "Final"  -- F
  end

  return f_description
end


------ DISSECTOR HELPERS ------
function parse_uint8(buf)
  local i = 0
  local val = 0

  val = buf(i, 1):uint()
  i = i + 1

  return val, i
end

function parse_zint(buf)
  local i = 0
  local val = 0

  repeat
    local tmp = buf(i, 1):uint()
    val = bit.bor(val, bit.lshift(bit.band(tmp, 0x7f), i * 7))
    i = i + 1
  until (bit.band(tmp, 0x80) == 0x00)

  return val, i
end

function parse_zbytes(buf)
  local i = 0

  local val, len = parse_zint(buf(i, -1))
  i = i + len

  if val > buf:len() - i then
    -- until the end of the buffer
    return buf(i, -1), buf:len(), val - buf:len()
  end

  return buf(i, val), i + val
end

function parse_zstring(buf)
  local i = 0

  local b_val, len = parse_zbytes(buf(i, -1))
  i = i + len

  return b_val:string(), i
end

function parse_reskey(tree, buf, is_k)
  local i = 0

  local subtree = tree:add("ResKey")
  local val, len = parse_zint(buf(i, -1))
  subtree:add(buf(i, len), "Resource ID: ", val)
  i = i + len

  if is_k == true then
    val, len = parse_zstring(buf(i, -1))
    subtree:add(buf(i, len), "Suffix: ", val)
    i = i + len
  end

  return i
end

function parse_payload(tree, buf)
  local i = 0

  local pl_val, pl_len = parse_zint(buf(i, -1))
  local p_val, p_len = parse_zbytes(buf(i, -1))
  local subtree = tree:add(buf(i, p_len), "Payload")
  subtree:add(buf(i, pl_len), "Length: ", pl_val)
  subtree:add(buf(i + pl_len, p_len - pl_len), "Payload: ", p_val:bytes():tohex())
  i = i + p_len

  return i
end

function parse_declare(tree, buf)
  local i = 0

  local a_size, len = parse_zint(buf(i, -1))
  tree:add(proto_zenoh.fields.declare_num_of_declaration, buf(i, len), a_size)
  i = i + len

  while a_size > 0 do
    local did = bit.band(buf(i, 1):uint(), 0x1F)

    if bit.band(did, 0X1F) == DECLARATION_ID.RESOURCE then
      local a_subtree = tree:add(buf(i, 1), "Declaration [" .. a_size .. "] = Resource Declaration")
      len = parse_declare_resource(a_subtree, buf(i, -1))
      i = i + len

    elseif bit.band(did, 0x1F) == DECLARATION_ID.PUBLISHER then
      local a_subtree = tree:add(buf(i, 1),"Declaration [" .. a_size .. "] = Publisher Declaration")
      len = parse_declare_publisher(a_subtree, buf(i, -1))
      i = i + len

    elseif bit.band(did, 0x1F) == DECLARATION_ID.SUBSCRIBER then
      local a_subtree = tree:add(buf(i, 1),"Declaration [" .. a_size .. "] = Subscriber Declaration")
      len = parse_declare_subscriber(a_subtree, buf(i, -1))
      i = i + len

    elseif bit.band(did, 0x1F) == DECLARATION_ID.QUERYABLE then
      local a_subtree = tree:add(buf(i, 1),"Declaration [" .. a_size .. "] = Queryable Declaration")
      len = parse_declare_queryable(a_subtree, buf(i, -1))
      i = i + len

    elseif bit.band(did, 0x1F) == DECLARATION_ID.FORGET_RESOURCE then
      local a_subtree = tree:add(buf(i, 1), "Declaration [" .. a_size .. "] = Forget Resource")
      len = parse_forget_resource(a_subtree, buf(i, -1))
      i = i + len

    elseif bit.band(did, 0x1F) == DECLARATION_ID.FORGET_PUBLISHER then
      local a_subtree = tree:add(buf(i, 1), "Declaration [" .. a_size .. "] = Forget Publisher")
      len = parse_forget_publisher(a_subtree, buf(i, -1))
      i = i + len

    elseif bit.band(did, 0x1F) == DECLARATION_ID.FORGET_SUBSCRIBER then
      local a_subtree = tree:add(buf(i, 1), "Declaration [" .. a_size .. "] = Forget Subscriber")
      len = parse_forget_subscriber(a_subtree, buf(i, -1))
      i = i + len

    elseif bit.band(did, 0x1F) == DECLARATION_ID.FORGET_QUERYABLE then
      local a_subtree = tree:add(buf(i, 1), "Declaration [" .. a_size .. "] = Forget Queryable")
      len = parse_forget_queryable(a_subtree, buf(i, -1))
      i = i + len

    end

    a_size = a_size - 1
  end

  return i
end

function parse_declare_flags(tree, buf, did)
  local f_bitwise = {0x04, 0x02, 0x01}
  d_flags = bit.rshift(buf(0,1):uint(), 5)

  local f_str = ""
  for i,v in ipairs(f_bitwise) do
    if did == DECLARATION_ID.RESOURCE then
      flag = get_declare_resource_flag_description(bit.band(d_flags, v))
    elseif did == DECLARATION_ID.PUBLISHER then
      flag = get_declare_publisher_flag_description(bit.band(d_flags, v))
    elseif did == DECLARATION_ID.SUBSCRIBER then
      flag = get_declare_subscriber_flag_description(bit.band(d_flags, v))
    elseif did == DECLARATION_ID.QUERYABLE then
      flag = get_declare_queryable_flag_description(bit.band(d_flags, v))
    elseif did == DECLARATION_ID.FORGET_RESOURCE then
      flag = get_forget_resource_flag_description(bit.band(d_flags, v))
    elseif did == DECLARATION_ID.FORGET_PUBLISHER then
      flag = get_forget_publisher_flag_description(bit.band(d_flags, v))
    elseif did == DECLARATION_ID.FORGET_SUBSCRIBER then
      flag = get_forget_subscriber_flag_description(bit.band(d_flags, v))
    elseif did == DECLARATION_ID.FORGET_QUERYABLE then
      flag = get_forget_queryable_flag_description(bit.band(d_flags, v))
    end

    if bit.band(d_flags, v) == v then
      f_str = f_str .. flag .. ", "
    end
  end

  tree:add(buf(0, 1), "Flags", d_flags):append_text(" (" .. f_str:sub(0, -3) .. ")") -- FIXME: print in hex
  -- TODO: add bitwise flag substree
end

function parse_declare_resource(tree, buf)
  local i = 0

  parse_declare_flags(tree, buf(i, 1), DECLARATION_ID.RESOURCE)
  i = i + 1

  local val, len = parse_zint(buf(i, -1))
  tree:add(buf(i, len), "Resource ID: ", val)
  i = i + len

  len = parse_reskey(tree, buf(i, -1), bit.band(d_flags, 0x04) == 0x04)
  i = i + len

  return i
end

function parse_declare_publisher(tree, buf)
  local i = 0

  parse_declare_flags(tree, buf(i, 1), DECLARATION_ID.PUBLISHER)
  i = i + 1

  local len = parse_reskey(tree, buf(i, -1), bit.band(d_flags, 0x04) == 0x04)
  i = i + len

  return i
end

function parse_declare_subscriber(tree, buf)
  local i = 0

  parse_declare_flags(tree, buf(i, 1), DECLARATION_ID.SUBSCRIBER)
  i = i + 1

  local len = parse_reskey(tree, buf(i, -1), bit.band(d_flags, 0x04) == 0x04)
  i = i + len

  if bit.band(h_flags, 0x02) == 0x02 then
    local submode = buf(i, 1):uint()
    tree:add(buf(i, 1), "SubMode: " .. bit.band(submode, 0x00):uint())
    local is_p = (bit.band(submode, 0x80) == 0x80)
    i = i + 1

    if is_p == true then
      local val, len = parse_zint(buf(i, -1))
      tree:add(buf(i, len), "Period Origin: ", val)
      i = i + len

      val, len = parse_zint(buf(i, -1))
      tree:add(buf(i, len), "Period Period: ", val)
      i = i + len

      val, len = parse_zint(buf(i, -1))
      tree:add(buf(i, len), "Period Duration: ", val)
      i = i + len
    end
  end

  return i
end

function parse_declare_queryable(tree, buf)
  local i = 0

  parse_declare_flags(tree, buf(i, 1), DECLARATION_ID.QUERYABLE)
  i = i + 1

  local len = parse_reskey(tree, buf(i, -1), bit.band(d_flags, 0x04) == 0x04)
  i = i + len

  local val, len = parse_zint(buf(i, -1))
  tree:add(buf(i, len), "Kind: ", val)
  i = i + len

  if bit.band(h_flags, 0x02) == 0x02 then
    local val, len = parse_zint(buf(i, -1))
    tree:add(buf(i, len), "Complete: ", val)
    i = i + len

    local val, len = parse_zint(buf(i, -1))
    tree:add(buf(i, len), "Distance: ", val)
    i = i + len
  end

  return i
end

function parse_forget_resource(tree, buf)
  local i = 0

  parse_declare_flags(tree, buf(i, 1), DECLARATION_ID.FORGET_RESOURCE)
  i = i + 1

  local val, len = parse_zint(buf(i, -1))
  tree:add(buf(i, len), "Resource ID: ", val)
  i = i + len

  return i
end

function parse_forget_publisher(tree, buf)
  local i = 0

  parse_declare_flags(tree, buf(i, 1), DECLARATION_ID.FORGET_PUBLISHER)
  i = i + 1

  local len = parse_reskey(tree, buf(i, -1), bit.band(d_flags, 0x04) == 0x04)
  i = i + len

  return i
end

function parse_forget_subscriber(tree, buf)
  local i = 0

  parse_declare_flags(tree, buf(i, 1), DECLARATION_ID.FORGET_SUBSCRIBER)
  i = i + 1

  local len = parse_reskey(tree, buf(i, -1), bit.band(d_flags, 0x04) == 0x04)
  i = i + len

  return i
end

function parse_forget_queryable(tree, buf)
  local i = 0

  parse_declare_flags(tree, buf(i, 1), DECLARATION_ID.FORGET_QUERYABLE)
  i = i + 1

  local len = parse_reskey(tree, buf(i, -1), bit.band(d_flags, 0x04) == 0x04)
  i = i + len

  local val, len = parse_zint(buf(i, -1))
  tree:add(buf(i, len), "Kind: ", val)
  i = i + len

  return i
end

function parse_data(tree, buf)
  local i = 0

  local len = parse_reskey(tree, buf(i, -1), bit.band(h_flags, 0x04) == 0x04)
  i = i + len

  if bit.band(h_flags, 0x02) == 0x02 then
    len = parse_datainfo(tree, buf(i, -1))
    i = i + len
  end

  local len = parse_payload(tree, buf(i, -1))
  i = i + len

  return i
end

function parse_link(tree, buf)
  local i = 0

  local val, len = parse_zint(buf(i, -1))
  tree:add(buf(i, len), "Link: ", val)
  i = i + len

  return i
end

function parse_links(tree, buf)
  local i = 0

  local a_size, len = parse_zint(buf(i, -1))
  subtree = tree:add(buf(i, len), "Links Size Array: ", a_size)
  i = i + len

  while a_size > 0 do
    len = parse_link(subtree, buf(i, -1))
    i = i + len

    a_size = a_size - 1
  end

  return i
end

function parse_locator(tree, buf)
  local i = 0

  val, len = parse_zstring(buf(i, -1))
  tree:add(buf(i, len), "Locator: ", val)
  i = i + len

  return i
end

function parse_locators(tree, buf)
  local i = 0

  local a_size, len = parse_zint(buf(i, -1))
  subtree = tree:add(buf(i, len), "Locators Size Array: ", a_size)
  i = i + len

  while a_size > 0 do
    len = parse_locator(subtree, buf(i, -1))
    i = i + len

    a_size = a_size - 1
  end

  return i
end

function parse_link_state_options(tree, buf)
  local i = 0

  local f_bitwise = {0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01}
  local o_flags = buf(0,1):uint()

  local f_str = ""
  for i,v in ipairs(f_bitwise) do
    flag = get_link_state_flag_description(bit.band(o_flags, v))

    if bit.band(o_flags, v) == v then
      f_str = f_str .. flag .. ", "
    end
  end

  tree:add(buf(0, 1), "Flags", o_flags):append_text(" (" .. f_str:sub(0, -3) .. ")") -- FIXME: print in hex
  -- TODO: add bitwise flag substree
  i = i + 1

  return o_flags, i
end


function parse_link_state(tree, buf)
  local i = 0

  local o_flags, len = parse_link_state_options(tree, buf(i, -1))
  i = i + len

  local val, len = parse_zint(buf(i, -1))
  tree:add(buf(i, len), "PS ID: ", val)
  i = i + len

  local val, len = parse_zint(buf(i, -1))
  tree:add(buf(i, len), "SN: ", val)
  i = i + len

  if bit.band(o_flags, 0x01) == 0x01 then
    local val, len = parse_zbytes(buf(i, -1))
    tree:add(buf(i, len), "Peer ID: ", val:bytes():tohex())
    i = i + len
  end

  if bit.band(o_flags, 0x02) == 0x02 then
    local val, len = parse_zint(buf(i, -1))
    tree:add(buf(i, len), "WhatAmI: ", val)
    i = i + len
  end

  if bit.band(o_flags, 0x04) == 0x04 then
    local len = parse_locators(tree, buf(i, -1))
    i = i + len
  end

  len = parse_links(tree, buf(i, -1))
  i = i + len

  return i
end

function parse_link_state_list(tree, buf)
  local i = 0

  local a_size, len = parse_zint(buf(i, -1))
  tree:add(proto_zenoh.fields.linkstatelist_size, buf(i, len), a_size)
  i = i + len

  while a_size > 0 do
    local a_subtree = tree:add(buf(i, 1), "Link State [" .. a_size .. "]")
    len = parse_link_state(a_subtree, buf(i, -1))
    i = i + len

    a_size = a_size - 1
  end

  return i
end

function parse_data_flags(tree, buf)
  local i = 0

  local f_bitwise = {0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01}
  local flags, len = parse_zint(buf(i, -1))
  i = i + len

  local f_str = ""
  for i,v in ipairs(f_bitwise) do
    flag = get_data_options_flag_description(bit.band(flags, v))

    if bit.band(flags, v) == v then
      f_str = f_str .. flag .. ", "
    end
  end

  tree:add(buf(i, len), "Flags", flags):append_text(" (" .. f_str:sub(0, -3) .. ")") -- FIXME: print in hex
  -- TODO: add bitwise flag substree

  return flags, i
end

function parse_datainfo(tree, buf)
  local i = 0

  local d_options, len = parse_data_options(tree, buf)
  i = i + len

  if bit.band(d_options, 0x01) == 0x01 then
    val, len = parse_zint(buf(i, -1))
    tree:add(buf(i, len), "Kind: ", val)
    i = i + len
  end

  if bit.band(d_options, 0x02) == 0x02 then
    val, len = parse_zint(buf(i, -1))
    tree:add(buf(i, len), "Encoding: ", val)
    i = i + len

    val, len = parse_zstring(buf(i, -1))
    tree:add(buf(i, len), "Encoding Suffix: ", val)
    i = i + len
  end

  if bit.band(d_options, 0x04) == 0x04 then
    len = parse_timestamp(tree, buf(i, -1))
    i = i + len
  end

  if bit.band(d_options, 0x80) == 0x80 then
    val, len = parse_zbytes(buf(i, -1))
    tree:add(buf(i, len), "Source ID: ", val:bytes():tohex())
    i = i + len
  end

  if bit.band(d_options, 0x100) == 0x100 then
    val, len = parse_zint(buf(i, -1))
    tree:add(buf(i, len), "Source SN: ", val)
    i = i + len
  end

  if bit.band(d_options, 0x200) == 0x200 then
    val, len = parse_zbytes(buf(i, -1))
    tree:add(buf(i, len), "First Router ID: ", val:bytes():tohex())
    i = i + len
  end

  if bit.band(d_options, 0x400) == 0x400 then
    val, len = parse_zint(buf(i, -1))
    tree:add(buf(i, len), "First Router SN: ", val)
    i = i + len
  end

  return i
end

function parse_timestamp(tree, buf)
  local i = 0

  local subtree = tree:add("Timestamp")

  val, len = parse_zint(buf(i, -1))
  subtree:add(buf(i, len), "Time: ", val)
  i = i + len

  val, len = parse_zbytes(buf(i, -1))
  subtree:add(buf(i, len), "ID: ", val:bytes():tohex())
  i = i + len

  return i
end

function parse_pull(tree, buf)
  local i = 0

  local len = parse_reskey(tree, buf(i, -1), bit.band(h_flags, 0x04) == 0x04)
  i = i + len

  local val, len = parse_zint(buf(i, -1))
  tree:add(proto_zenoh.fields.pull_pullid, buf(i, len), val)
  i = i + len

  if bit.band(h_flags, 0x02) == 0x02 then
    val, len = parse_zint(buf(i, -1))
    tree:add(proto_zenoh.fields.pull_maxsamples, buf(i, len), val)
    i = i + len
  end

  return i
end

function parse_unit(tree, buf)
  local i = 0

  -- Currently, UNIT message does not have payload

  return i
end

function parse_query(tree, buf)
  local i = 0

  local len = parse_reskey(tree, buf(i, -1), bit.band(h_flags, 0x04) == 0x04)
  i = i + len

  local val, len = parse_zstring(buf(i, -1))
  tree:add(proto_zenoh.fields.query_predicate, buf(i, len), val)
  i = i + len

  val, len = parse_zint(buf(i, -1))
  tree:add(proto_zenoh.fields.query_qid, buf(i, len), val)
  i = i + len

  if bit.band(h_flags, 0x01) == 0x01 then
    len = parse_query_target(tree, buf(i, -1))
    i = i + len
  end

  len = parse_query_consolidation(tree, buf(i, -1))
  i = i + len

  return i
end

function parse_query_target(tree, buf)
  local i = 0

  local subtree = tree:add("Target")
  subtree:add(buf(i, 1), "Kind: ", buf(i, 1))
  i = i + 1

  len = parse_target(subtree, buf(i, -1))
  i = i + len

  return i
end

function parse_target(tree, buf)
  local i = 0

  local val = buf(i, 1)
  if val == 0 then
    tree:add(buf(i, 1), "Tag: Best Matching (0)")
  elseif val == 1 then
    tree:add(buf(i, 1), "Tag: Complete (1)")
  elseif val == 2 then
    tree:add(buf(i, 1), "Tag: All (2)")
  elseif val == 3 then
    tree:add(buf(i, 1), "Tag: None (3)")
  end
  i = i + 1

  tree:add(buf(i, 1), "Complete: ", buf(i, 1))
  i = i + 1

  return i
end

function parse_query_consolidation(tree, buf)
  local i = 0

  local subtree = tree:add("Consolidation")
  local val = buf(i, 1)

  -- FIXME: make this cleaner with a constants array
  for k = 0,2,1 do
    local field = ""
    if k == 0 then
      field = "First Routers: "
    elseif k == 1 then
      field = "Last Router: "
    elseif k == 2 then
      field = "Reception: "
    end

    if bit.band(bit.rshift(val:uint(), k * 2), 0x03) == 0x00 then
      subtree:add(buf(i, 1), field .. "None (0)")
    elseif bit.band(bit.rshift(val:uint(), k * 2), 0x03) == 0x01 then
      subtree:add(buf(i, 1), field .. "Lazy (1)")
    elseif bit.band(bit.rshift(val:uint(), k * 2), 0x03) == 0x02 then
      subtree:add(buf(i, 1), field .. "Full (2)")
    end
  end
  i = i + 1

  return i
end

function parse_initial_sn_qos(tree, buf)
  local i = 0

  local a_size = PRIORITY_NUM
  subtree = tree:add(buf(i, len), "Initial SN Array: ", a_size)

  while a_size > 0 do
    len = parse_initial_sn_plain(subtree, buf(i, -1))
    i = i + len

    a_size = a_size - 1
  end

  return i
end

function parse_initial_sn_plain(tree, buf)
  local i = 0

  local val, len = parse_zint(buf(i, -1))
  subtree = tree:add(buf(i, len), "Reliable: ", val)
  i = i + len

  local val, len = parse_zint(buf(i, -1))
  subtree = tree:add(buf(i, len), "Best Effort: ", val)
  i = i + len

  return i
end

-------------------------------------------------------------------------------
function parse_init(tree, buf)
  local i = 0

  if bit.band(h_flags, 0x04) == 0x04 then
    o_flags, len = parse_zint(buf(i, -1))

    local f_str = ""
    local f_bitwise = {0x800, 0x400, 0x200, 0x100, 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01} -- FIXME: make it cleaner
    for i,v in ipairs(f_bitwise) do
      flag = get_options_flag_description(bit.band(o_flags, v))

      if bit.band(o_flags, v) == v then
        f_str = f_str .. flag .. ", "
      end
    end

    i = i + len
  end

  if bit.band(h_flags, 0x01) == 0x00 then
    tree:add(proto_zenoh.fields.init_vmaj, buf(i, 1), bit.rshift(buf(i, 1):uint(), 4))
    tree:add(proto_zenoh.fields.init_vmin, buf(i, 1), bit.band(buf(i, 1):uint(), 0xff))
    i = i + 1
  end

  local val, len = parse_zint(buf(i, -1))
  tree:add(proto_zenoh.fields.init_whatami, buf(i, len), val)
  i = i + len

  val, len = parse_zbytes(buf(i, -1))
  tree:add(proto_zenoh.fields.init_peerid, val)
  i = i + len

  if bit.band(h_flags, 0x02) == 0x02 then
    val, len = parse_zint(buf(i, -1))
    tree:add(proto_zenoh.fields.init_snresolution, buf(i, len), val)
    i = i + len
  end

  if bit.band(h_flags, 0x01) == 0x01 then
    val, len = parse_zbytes(buf(i, -1))
    tree:add(proto_zenoh.fields.init_cookie, val)
    i = i + len
  end

  return i
end

function parse_open(tree, buf)
  local i = 0

  local val, len = parse_zint(buf, i)
  if bit.band(h_flags, 0x02) == 0x02 then
    tree:add(proto_zenoh.fields.open_lease, buf(i, len), val):append_text(" seconds")
  else
    tree:add(proto_zenoh.fields.open_lease, buf(i, len), val):append_text(" microseconds")
  end
  i = i + len

  val, len = parse_zint(buf(i, -1))
  tree:add(proto_zenoh.fields.open_initialsn, buf(i, len), val)
  i = i + len

  if bit.band(h_flags, 0x01) == 0x00 then
    val, len = parse_zbytes(buf(i, -1))
    tree:add(proto_zenoh.fields.open_cookie, val)
    i = i + len
  end

  return i
end

function parse_close(tree, buf)
  local i = 0

  if bit.band(h_flags, 0x01) == 0x01 then
    val, len = parse_zbytes(buf(i, -1))
    tree:add(proto_zenoh.fields.close_peerid, val)
    i = i + len
  end

  val, len = parse_zint(buf(i, -1))
  tree:add(proto_zenoh.fields.close_reason, buf(i, len), val)
  i = i + len

  return i
end

function parse_sync(tree, buf)
  local i = 0

  local val, len = parse_zint(buf(i, -1))
  tree:add(proto_zenoh.fields.sync_sn, buf(i, len), val)
  i = i + len

  if bit.band(h_flags, 0x01) == 0x01 and bit.band(h_flags, 0x02) == 0x02 then
    local val, len = parse_zint(buf(i, -1))
    tree:add(proto_zenoh.fields.sync_count, buf(i, len), val)
    i = i + len
  end

  return i
end

function parse_acknack(tree, buf)
  local i = 0

  local val, len = parse_zint(buf(i, -1))
  tree:add(proto_zenoh.fields.acknack_sn, buf(i, len), val)
  i = i + len

  if bit.band(h_flags, 0x01) == 0x01 then
    local val, len = parse_zint(buf(i, -1))
    tree:add(proto_zenoh.fields.acknack_mask, buf(i, len), val)
    i = i + len
  end

  return i
end

function parse_join(tree, buf)
  local i = 0

  local o_flags
  if bit.band(h_flags, 0x04) == 0x04 then
    o_flags, len = parse_zint(buf(i, -1))

    local f_bitwise = {0x800, 0x400, 0x200, 0x100, 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01} -- FIXME: make it cleaner
    local f_str = ""
    for i,v in ipairs(f_bitwise) do
      flag = get_options_flag_description(bit.band(o_flags, v))

      if bit.band(o_flags, v) == v then
        f_str = f_str .. flag .. ", "
      end
    end

    i = i + len
  end

  if bit.band(h_flags, 0x01) == 0x00 then
    tree:add(proto_zenoh.fields.join_vmaj, buf(i, 1), bit.rshift(buf(i, 1):uint(), 4))
    tree:add(proto_zenoh.fields.join_vmin, buf(i, 1), bit.band(buf(i, 1):uint(), 0xff))
    i = i + 1
  end

  local val, len = parse_zint(buf(i, -1))
  tree:add(proto_zenoh.fields.join_whatami, buf(i, len), val)
  i = i + len

  val, len = parse_zbytes(buf(i, -1))
  tree:add(proto_zenoh.fields.join_peerid, val)
  i = i + len

  local val, len = parse_zint(buf, i)
  if bit.band(h_flags, 0x02) == 0x02 then
    tree:add(proto_zenoh.fields.join_lease, buf(i, len), val):append_text(" seconds")
  else
    tree:add(proto_zenoh.fields.join_lease, buf(i, len), val):append_text(" microseconds")
  end
  i = i + len

  if bit.band(h_flags, 0x02) == 0x02 then
    val, len = parse_zint(buf(i, -1))
    tree:add(proto_zenoh.fields.join_snresolution, buf(i, len), val)
    i = i + len
  end

  if bit.band(o_flags, 0x01) == 0x01 then
    local len = parse_initial_sn_qos(tree, buf(i, -1))
    i = i + len
  else
    local len = parse_initial_sn_plain(tree, buf(i, -1))
    i = i + len
  end

  return i
end

function parse_scout(tree, buf)
  local i = 0

  val, len = parse_uint8(buf(i, -1))
  tree:add(proto_zenoh.fields.scout_version, buf(i, len), val)
  i = i + len

  val, len = parse_uint8(buf(i, -1))
  tree:add(proto_zenoh.fields.scout_what, buf(i, len), bit.band(val, 0x07))
  i = i + len

  if bit.band(h_flags, 0x01) == 0x01 then
    local val, len = parse_zbytes(buf(i, -1))
    tree:add(proto_zenoh.fields.scout_zenohid, val)
    i = i + len
  end

  return i
end

function parse_hello(tree, buf)
  local i = 0

  if bit.band(h_flags, 0x01) == 0x01 then
    local val, len = parse_zbytes(buf(i, -1))
    tree:add(proto_zenoh.fields.hello_peerid, val)
    i = i + len
  end

  if bit.band(h_flags, 0x02) == 0x02 then
    local val, len = parse_zint(buf(i, -1))
    tree:add(proto_zenoh.fields.hello_whatami, buf(i, len), val)
    i = i + len
  end

  if bit.band(h_flags, 0x04) == 0x04 then
    local len = parse_locators(tree, buf(i, -1))
    i = i + len
  end

  return i
end

function parse_keepalive(tree, buf)
  local i = 0

  if bit.band(h_flags, 0x01) == 0x01 then
    val, len = parse_zbytes(buf(i, -1))
    tree:add(proto_zenoh.fields.keepalive_peerid, val)
    i = i + len
  end

  return i
end

function parse_pingpong(tree, buf)
  local i = 0

  local val, len = parse_zint(buf, i)
  tree:add(proto_zenoh.fields.pingpong_hash, buf(i, len), val)
  i = i + len

  return i
end

function parse_frame(tree, buf, f_size)
  local i = 0

  local val, len = parse_zint(buf(i, -1))
  tree:add(proto_zenoh.fields.frame_sn, buf(i, len), val)
  i = i + len

  if bit.band(h_flags, 0x02) == 0x02 then
    local is_first_fragment = true
    for _, v in pairs(pending_fragments) do
      if v == val  then
        is_first_fragment = false
        break
      end
    end

    if is_first_fragment == true then
      len = decode_message(tree, buf(i, -1))
      i = i + len
    else
      tree:add(buf(i, -1), "Fragmented message (continuation): ", buf(i, -1))
      i = buf:len()
    end

    if bit.band(h_flags, 0x04) ~= 0x04 then
      table.insert(pending_fragments, val + 1)
    end

  else
    repeat
      len = decode_message(tree, buf(i, -1))
      i = i + len
    until i == f_size + 1
  end

  return i
end

function parse_routing_context(tree, buf)
  local i = 0

  local val, len = parse_zint(buf, i)
  tree:add(proto_zenoh.fields.routingcontext_tid, buf(i, len), val)
  i = i + len

  return i
end

function parse_reply_context(tree, buf)
  local i = 0

  local val, len = parse_zint(buf, i)
  tree:add(proto_zenoh.fields.replycontext_qid, buf(i, len), val)
  i = i + len

  if bit.band(h_flags, 0x01) == 0x00 then
    local val, len = parse_zint(buf(i, -1))
    tree:add(proto_zenoh.fields.replycontext_replierkind, buf(i, len), val)
    i = i + len
  end

  if bit.band(h_flags, 0x01) == 0x00 then
    local val, len = parse_zbytes(buf(i, -1))
    tree:add(proto_zenoh.fields.replycontext_replierid, buf(i, len), val)
    i = i + len
  end

  return i
end

function parse_attachment(tree, buf)
  local i = 0

  local len = parse_payload(tree, buf(i, -1))
  i = i + len

  return i
end

function parse_header_enc(tree, buf)
  local enc = bit.rshift(buf(0,1):uint(), 5)
  local s_enc = ""
  if enc == 0x00 then
    s_enc = "Zenoh Properties"
  end

  tree:add(buf(0, 1), s_enc, buf(0, 1))
end

function parse_header_id(tree, buf)
  local id = bit.rshift(buf(0,1):uint(), 5)

  tree:add(buf(0, 1), "ID:", id, buf(0, 1))
end

function parse_header_flags(tree, buf, msgid)
  local f_bitwise = {0x04, 0x02, 0x01}
  h_flags = bit.rshift(buf(0,1):uint(), 5)

  local f_str = ""
  for i,v in ipairs(f_bitwise) do
    if msgid == ZENOH_MSGID.DECLARE then
      flag = get_declare_flag_description(bit.band(h_flags, v))
    elseif msgid == ZENOH_MSGID.DATA then
      flag = get_data_flag_description(bit.band(h_flags, v))
    elseif msgid == ZENOH_MSGID.QUERY then
      flag = get_query_flag_description(bit.band(h_flags, v))
    elseif msgid == ZENOH_MSGID.PULL then
      flag = get_pull_flag_description(bit.band(h_flags, v))
    elseif msgid == ZENOH_MSGID.UNIT then
      flag = get_unit_flag_description(bit.band(h_flags, v))
    elseif msgid == ZENOH_MSGID.LINK_STATE_LIST then
      flag = get_linkstatelist_flag_description(bit.band(h_flags, v))
    elseif msgid == SESSION_MSGID.JOIN then
      flag = get_join_flag_description(bit.band(h_flags, v))
    elseif msgid == SESSION_MSGID.SCOUT then
      flag = get_scout_flag_description(bit.band(h_flags, v))
    elseif msgid == SESSION_MSGID.HELLO then
      flag = get_hello_flag_description(bit.band(h_flags, v))
    elseif msgid == SESSION_MSGID.INIT then
      flag = get_init_flag_description(bit.band(h_flags, v))
    elseif msgid == SESSION_MSGID.OPEN then
      flag = get_open_flag_description(bit.band(h_flags, v))
    elseif msgid == SESSION_MSGID.CLOSE then
      flag = get_close_flag_description(bit.band(h_flags, v))
    elseif msgid == SESSION_MSGID.SYNC then
      flag = get_sync_flag_description(bit.band(h_flags, v))
    elseif msgid == SESSION_MSGID.ACK_NACK then
      flag = get_acknack_flag_description(bit.band(h_flags, v))
    elseif msgid == SESSION_MSGID.KEEP_ALIVE then
      flag = get_keepalive_flag_description(bit.band(h_flags, v))
    elseif msgid == SESSION_MSGID.PING_PONG then
      flag = get_pingpong_flag_description(bit.band(h_flags, v))
    elseif msgid == SESSION_MSGID.FRAME then
      flag = get_frame_flag_description(bit.band(h_flags, v))
    elseif msgid == DECORATORS_MSGID.ATTACHMENT then
      flag = get_attachment_flag_description(bit.band(h_flags, v))
    elseif msgid == DECORATORS_MSGID.ROUTING_CONTEXT then
      flag = get_routingcontext_flag_description(bit.band(h_flags, v))
    elseif msgid == DECORATORS_MSGID.REPLY_CONTEXT then
      flag = get_replycontext_flag_description(bit.band(h_flags, v))
    end

    if bit.band(h_flags, v) == v then
      f_str = f_str .. flag .. ", "
    end
  end

  if msgid == ZENOH_MSGID.DECLARE then
    tree:add(proto_zenoh.fields.declare_flags, buf(0, 1), h_flags):append_text(" (" .. f_str:sub(0, -3) .. ")")
  elseif msgid == ZENOH_MSGID.DATA then
    tree:add(proto_zenoh.fields.data_flags, buf(0, 1), h_flags):append_text(" (" .. f_str:sub(0, -3) .. ")")
  elseif msgid == ZENOH_MSGID.QUERY then
    tree:add(proto_zenoh.fields.query_flags, buf(0, 1), h_flags):append_text(" (" .. f_str:sub(0, -3) .. ")")
  elseif msgid == ZENOH_MSGID.PULL then
    tree:add(proto_zenoh.fields.pull_flags, buf(0, 1), h_flags):append_text(" (" .. f_str:sub(0, -3) .. ")")
  elseif msgid == ZENOH_MSGID.UNIT then
    tree:add(proto_zenoh.fields.unit_flags, buf(0, 1), h_flags):append_text(" (" .. f_str:sub(0, -3) .. ")")
  elseif msgid == ZENOH_MSGID.LINK_STATE_LIST then
    tree:add(proto_zenoh.fields.linkstatelist_flags, buf(0, 1), h_flags):append_text(" (" .. f_str:sub(0, -3) .. ")")
  elseif msgid == SESSION_MSGID.JOIN then
    tree:add(proto_zenoh.fields.join_flags, buf(0, 1), h_flags):append_text(" (" .. f_str:sub(0, -3) .. ")")
  elseif msgid == SESSION_MSGID.SCOUT then
    tree:add(proto_zenoh.fields.scout_flags, buf(0, 1), h_flags):append_text(" (" .. f_str:sub(0, -3) .. ")")
  elseif msgid == SESSION_MSGID.HELLO then
    tree:add(proto_zenoh.fields.hello_flags, buf(0, 1), h_flags):append_text(" (" .. f_str:sub(0, -3) .. ")")
  elseif msgid == SESSION_MSGID.INIT then
    tree:add(proto_zenoh.fields.init_flags, buf(0, 1), h_flags):append_text(" (" .. f_str:sub(0, -3) .. ")")
  elseif msgid == SESSION_MSGID.OPEN then
    tree:add(proto_zenoh.fields.open_flags, buf(0, 1), h_flags):append_text(" (" .. f_str:sub(0, -3) .. ")")
  elseif msgid == SESSION_MSGID.CLOSE then
    tree:add(proto_zenoh.fields.close_flags, buf(0, 1), h_flags):append_text(" (" .. f_str:sub(0, -3) .. ")")
  elseif msgid == SESSION_MSGID.SYNC then
    tree:add(proto_zenoh.fields.sync_flags, buf(0, 1), h_flags):append_text(" (" .. f_str:sub(0, -3) .. ")")
  elseif msgid == SESSION_MSGID.ACK_NACK then
    tree:add(proto_zenoh.fields.acknack_flags, buf(0, 1), h_flags):append_text(" (" .. f_str:sub(0, -3) .. ")")
  elseif msgid == SESSION_MSGID.KEEP_ALIVE then
    tree:add(proto_zenoh.fields.keepalive_flags, buf(0, 1), h_flags):append_text(" (" .. f_str:sub(0, -3) .. ")")
  elseif msgid == SESSION_MSGID.PING_PONG then
    tree:add(proto_zenoh.fields.pingpong_flags, buf(0, 1), h_flags):append_text(" (" .. f_str:sub(0, -3) .. ")")
  elseif msgid == SESSION_MSGID.FRAME then
    tree:add(proto_zenoh.fields.frame_flags, buf(0, 1), h_flags):append_text(" (" .. f_str:sub(0, -3) .. ")")
  elseif msgid == DECORATORS_MSGID.ATTACHMENT then
    tree:add(proto_zenoh.fields.attachment_flags, buf(0, 1), h_flags):append_text(" (" .. f_str:sub(0, -3) .. ")")
  elseif msgid == DECORATORS_MSGID.ROUTING_CONTEXT then
    tree:add(proto_zenoh.fields.routingcontext_flags, buf(0, 1), h_flags):append_text(" (" .. f_str:sub(0, -3) .. ")")
  elseif msgid == DECORATORS_MSGID.REPLY_CONTEXT then
    tree:add(proto_zenoh.fields.replycontext_flags, buf(0, 1), h_flags):append_text(" (" .. f_str:sub(0, -3) .. ")")
  end

  -- TODO: add bitwise flag substree
end

function parse_msgid(tree, buf)
  local msgid = bit.band(buf(i, 1):uint(), 0x1F)

  if msgid == ZENOH_MSGID.DECLARE then
    tree:add(proto_zenoh.fields.header_msgid, buf(i, 1), msgid, base.u8, "(Declare)")
    return ZENOH_MSGID.DECLARE
  elseif msgid == ZENOH_MSGID.DATA then
    tree:add(proto_zenoh.fields.header_msgid, buf(i, 1), msgid, base.u8, "(Data)")
    return ZENOH_MSGID.DATA
  elseif msgid == ZENOH_MSGID.QUERY then
    tree:add(proto_zenoh.fields.header_msgid, buf(i, 1), msgid, base.u8, "(Query)")
    return ZENOH_MSGID.QUERY
  elseif msgid == ZENOH_MSGID.PULL then
    tree:add(proto_zenoh.fields.header_msgid, buf(i, 1), msgid, base.u8, "(Pull)")
    return ZENOH_MSGID.PULL
  elseif msgid == ZENOH_MSGID.UNIT then
    tree:add(proto_zenoh.fields.header_msgid, buf(i, 1), msgid, base.u8, "(Unit)")
    return ZENOH_MSGID.UNIT
  elseif msgid == ZENOH_MSGID.LINK_STATE_LIST then
    tree:add(proto_zenoh.fields.header_msgid, buf(i, 1), msgid, base.u8, "(LinkStateList)")
    return ZENOH_MSGID.LINK_STATE_LIST
  elseif msgid == SESSION_MSGID.SCOUT then
    tree:add(proto_zenoh.fields.header_msgid, buf(i, 1), msgid, base.u8, "(Scout)")
    return SESSION_MSGID.SCOUT
  elseif msgid == SESSION_MSGID.HELLO then
    tree:add(proto_zenoh.fields.header_msgid, buf(i, 1), msgid, base.u8, "(Hello)")
    return SESSION_MSGID.HELLO
  elseif msgid == SESSION_MSGID.INIT then
    tree:add(proto_zenoh.fields.header_msgid, buf(i, 1), msgid, base.u8, "(Init)")
    return SESSION_MSGID.INIT
  elseif msgid == SESSION_MSGID.OPEN then
    tree:add(proto_zenoh.fields.header_msgid, buf(i, 1), msgid, base.u8, "(Open)")
    return SESSION_MSGID.OPEN
  elseif msgid == SESSION_MSGID.CLOSE then
    tree:add(proto_zenoh.fields.header_msgid, buf(i, 1), msgid, base.u8, "(Close)")
    return SESSION_MSGID.CLOSE
  elseif msgid == SESSION_MSGID.SYNC then
    tree:add(proto_zenoh.fields.header_msgid, buf(i, 1), msgid, base.u8, "(Sync)")
    return SESSION_MSGID.SYNC
  elseif msgid == SESSION_MSGID.ACK_NACK then
    tree:add(proto_zenoh.fields.header_msgid, buf(i, 1), msgid, base.u8, "(ACK-NACK)")
    return SESSION_MSGID.ACK_NACK
  elseif msgid == SESSION_MSGID.KEEP_ALIVE then
    tree:add(proto_zenoh.fields.header_msgid, buf(i, 1), msgid, base.u8, "(Keep Alive)")
    return SESSION_MSGID.KEEP_ALIVE
  elseif msgid == SESSION_MSGID.PING_PONG then
    tree:add(proto_zenoh.fields.header_msgid, buf(i, 1), msgid, base.u8, "(Ping Pong)")
    return SESSION_MSGID.PING_PONG
  elseif msgid == SESSION_MSGID.FRAME then
    tree:add(proto_zenoh.fields.header_msgid, buf(i, 1), msgid, base.u8, "(Frame)")
    return SESSION_MSGID.FRAME
  elseif msgid == DECORATORS_MSGID.PRIORITY then
    tree:add(proto_zenoh.fields.header_msgid, buf(i, 1), msgid, base.u8, "(Priority)")
    return DECORATORS_MSGID.PRIORITY
  elseif msgid == DECORATORS_MSGID.ROUTING_CONTEXT then
    tree:add(proto_zenoh.fields.header_msgid, buf(i, 1), msgid, base.u8, "(Routing Context)")
    return DECORATORS_MSGID.ROUTING_CONTEXT
  elseif msgid == DECORATORS_MSGID.REPLY_CONTEXT then
    tree:add(proto_zenoh.fields.header_msgid, buf(i, 1), msgid, base.u8, "(Reply Context)")
    return DECORATORS_MSGID.REPLY_CONTEXT
  elseif msgid == DECORATORS_MSGID.ATTACHMENT then
    tree:add(proto_zenoh.fields.header_msgid, buf(i, 1), msgid, base.u8, "(Attachment)")
    return DECORATORS_MSGID.ATTACHMENT
  end

  return NULL
end

function parse_header(tree, buf)
  local i = 0

  local msgid = parse_msgid(tree, buf(i, 1))
  if msgid == DECORATORS_MSGID.ATTACHMENT then
    parse_header_enc(tree, buf(i, 1))
  elseif msgid == DECORATORS_MSGID.PRIORITY then
    parse_header_id(tree, buf(i, 1))
  else
    parse_header_flags(tree, buf(i, 1), msgid)
  end
  i = i + 1

  return msgid, i
end

function decode_message(tree, buf)
  local i = 0

  local h_subtree = tree:add(proto_zenoh, buf(i, 1), "Header")
  local msgid, len = parse_header(h_subtree, buf(i, 1))
  i = i + len

  -- NO PAYLOAD
  if i == buf:len() then
    return len
  end

  if msgid == DECORATORS_MSGID.PRIORITY then
    return len
  end

  -- PAYLOAD
  local p_subtree = tree:add(proto_zenoh, buf(i, -1), "Payload")

  if msgid == ZENOH_MSGID.DECLARE then
    len = parse_declare(p_subtree, buf(i, -1))
  elseif msgid == ZENOH_MSGID.DATA then
    len = parse_data(p_subtree, buf(i, -1))
  elseif msgid == ZENOH_MSGID.QUERY then
    len = parse_query(p_subtree, buf(i, -1))
  elseif msgid == ZENOH_MSGID.PULL then
    len = parse_pull(p_subtree, buf(i, -1))
  elseif msgid == ZENOH_MSGID.UNIT then
    len = parse_unit(p_subtree, buf(i, -1))
  elseif msgid == ZENOH_MSGID.LINK_STATE_LIST then
    len = parse_link_state_list(p_subtree, buf(i, -1))
  elseif msgid == SESSION_MSGID.JOIN then
    len = parse_join(p_subtree, buf(i, -1))
  elseif msgid == SESSION_MSGID.SCOUT then
    len = parse_scout(p_subtree, buf(i, -1))
  elseif msgid == SESSION_MSGID.HELLO then
    len = parse_hello(p_subtree, buf(i, -1))
  elseif msgid == SESSION_MSGID.INIT then
    len = parse_init(p_subtree, buf(i, -1))
  elseif msgid == SESSION_MSGID.OPEN then
    len = parse_open(p_subtree, buf(i, -1))
  elseif msgid == SESSION_MSGID.CLOSE then
    len = parse_close(p_subtree, buf(i, -1))
  elseif msgid == SESSION_MSGID.SYNC then
    len = parse_sync(p_subtree, buf(i, -1))
  elseif msgid == SESSION_MSGID.ACK_NACK then
    len = parse_acknack(p_subtree, buf(i, -1))
  elseif msgid == SESSION_MSGID.KEEP_ALIVE then
    len = parse_keepalive(p_subtree, buf(i, -1))
  elseif msgid == SESSION_MSGID.PING_PONG then
    len = parse_pingpong(p_subtree, buf(i, -1))
  elseif msgid == SESSION_MSGID.FRAME then
    len = parse_frame(p_subtree, buf(i, -1), buf:len())
  elseif msgid == DECORATORS_MSGID.ROUTING_CONTEXT then
    len = parse_routing_context(p_subtree, buf(i, -1), buf:len())
  elseif msgid == DECORATORS_MSGID.REPLY_CONTEXT then
    len = parse_reply_context(p_subtree, buf(i, -1), buf:len())
  elseif msgid == DECORATORS_MSGID.ATTACHMENT then
    len = parse_attachment(p_subtree, buf(i, -1), buf:len())
  end
  i = i + len

  return i
end


---------- DISSECTOR ----------
function dissector(buf, pinfo, root, is_tcp)
  local i = 0

  if buf:len() < 2 and is_tcp == true then return
  elseif buf:len() == 0 and (is_tcp == false or is_frame == true) then return end

  pinfo.cols.protocol = proto_zenoh.name

    tree = root:add(proto_zenoh, buf())

    local f_size = buf():len()
    if is_tcp == true then
      f_size = buf(i, 2):le_uint()
      tree:add_le(proto_zenoh_tcp.fields.len, buf(i, 2), f_size)
      i = i + 2
    end

    if f_size > buf:len() - (is_tcp == true and 2 or 0) then
      pinfo.desegment_offset = 0
      pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
      return
    end

  while i < buf:len() do
    len = decode_message(tree, buf(i, f_size - i))
    i = i + len
  end
  return 0
end

function proto_zenoh_udp.dissector(buf, pinfo, root)
    dissector(buf, pinfo, root, false)
end

function proto_zenoh_tcp.dissector(buf, pinfo, root)
    dissector(buf, pinfo, root, true)
end

-- register zenoh to handle ports
--  * 7447/tcp : the zenoh protocol via TCP
--  * 7447/udp : the zenoh scouting protocol using UDP multicast
do
    local tcp_port_table = DissectorTable.get("tcp.port")
    tcp_port_table:add(7447, proto_zenoh_tcp)

    local udp_port_table = DissectorTable.get("udp.port")
    udp_port_table:add(7447, proto_zenoh_udp)
end


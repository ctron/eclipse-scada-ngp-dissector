/* packet-foo.c
 * Routines for HP 2101nw wireless USB print server 
 * packet disassembly
 * Copyright (c) 2011 Reinhold Kainhofer <reinhold@kainhofer.com>
 * 
 * Base on packet-interlink.c:
 * Routines for Interlink protocol packet disassembly
 * By Uwe Girlich <uwe.girlich@philosys.de>
 * Copyright 2010 Uwe Girlich
 *
 * $Id: packet-foo.c 35224 2010-12-20 05:35:29Z guy $
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include <config.h>
#include <epan/packet.h>
#include <epan/dissectors/packet-tcp.h>

#define NGP_PORT 2101
#define FRAME_HEADER_LEN 6

static int proto_ngp = -1;
static gint ett_ngp = -1;

/* Variables for ngp packets */
static int hf_ngp_field_version = -1;
static int hf_ngp_field_type = -1;
static int hf_ngp_field_length = -1;
static int hf_ngp_field_data = -1;

/* Displayed names of commands */
static const value_string strings_field_type[] = {
  { 0x00, "HELLO" },
  { 0x01, "MESSAGE" },
  { 0x02, "ACCEPT" },
  { 0x03, "CLOSE" },
  { 0x04, "START" },
  { 0x05, "PING" },
  { 0x06, "PONG" },
  { 0x00, NULL }
};



static guint get_ngp_message_len(packet_info *pinfo, tvbuff_t *tvb, int offset)
{
   guint len = (guint)tvb_get_ntohl(tvb, offset+2);
   return len + FRAME_HEADER_LEN;
}

static void
dissect_ngp_message (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  gint offset = 0;
  guint8 cmdtype = tvb_get_guint8 (tvb, 0);

  /* TODO: Some sanity checking to determine whether the packet is really
   *       an ngp communication packet */
  if (/*not an ngp packet*/FALSE)
    return/* 0*/;
  /* TODO: How do we detect answers by the device? They don't have any
   *       custom header or standardized format! */


  col_set_str (pinfo-> cinfo, COL_PROTOCOL, "Eclipse SCADA NGP");
  col_clear (pinfo->cinfo, COL_INFO);

  if (tree) {
    proto_item *ti = NULL;
    proto_item *ngp_tree = NULL;

    ti = proto_tree_add_item (tree, proto_ngp, tvb, 0, -1, ENC_NA);
    ngp_tree = proto_item_add_subtree (ti, ett_ngp);
    proto_tree_add_item (ngp_tree, hf_ngp_field_version, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item (ngp_tree, hf_ngp_field_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    guint32 len = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item (ngp_tree, hf_ngp_field_length, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if ( len > 0 ) {
       proto_tree_add_item (ngp_tree, hf_ngp_field_data, tvb, offset, len, ENC_NA);
       offset += len;
    }
    /* TODO: Implement further packet fields here */

    //return offset;
  }
  // return tvb_length(tvb);
}

static int
dissect_ngp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * data)
{
   tcp_dissect_pdus(tvb, pinfo, tree, TRUE, FRAME_HEADER_LEN,
      get_ngp_message_len, dissect_ngp_message);
   return tvb_length(tvb);
}

void
proto_register_ngp(void)
{
  static hf_register_info hf_ngp[] = {
    { &hf_ngp_field_version,
        { "Version", "ngp.mc.version",
          FT_UINT8, BASE_DEC_HEX,
          NULL, 0x0,
          NULL, HFILL },
    },
    { &hf_ngp_field_type,
        { "Type", "ngp.mc.type",
          FT_UINT8, BASE_DEC_HEX,
          VALS(strings_field_type), 0x0,
          NULL, HFILL },
    },
    { &hf_ngp_field_length,
        { "Data Length", "ngp.mc.length",
          FT_INT32, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL },
    },
    { &hf_ngp_field_data,
        { "Data", "ngp.mc.data",
          FT_BYTES, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL },
    }
    
  };
  static gint *ett_ngp_arr[] = { /* protocol subtree array */
    &ett_ngp
  };
  proto_ngp = proto_register_protocol(
    "Eclipse SCADA NGP Message Channel", "ngp", "ngp");
  proto_register_field_array (proto_ngp, hf_ngp, array_length (hf_ngp));
  proto_register_subtree_array (ett_ngp_arr, array_length (ett_ngp_arr));
}

void
proto_reg_handoff_ngp_ngp(void)
{
  static dissector_handle_t ngp_handle;
  ngp_handle = new_create_dissector_handle (dissect_ngp, proto_ngp);
  dissector_add_uint ("tcp.port", NGP_PORT, ngp_handle);
}


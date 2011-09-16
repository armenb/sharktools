/* frame_data.c
 * Routines for packet disassembly
 *
 * $Id: frame_data.c 33614 2010-07-22 09:14:24Z guy $
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
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

/*
 * APB: this file contains several functions from wireshark-1.4.0/epan/frame_data.c 
 * that were backported to accomodate wireshark-0.99.5, 1.0.*, and 1.2.*
 *
 * We only want to include the content of this file if we are < 1.4.0 (or there
 * will be redefinitions)
 */
#if (WIRESHARK_0_99_5 || WIRESHARK_1_0_0 || WIRESHARK_1_2_0)

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <wiretap/wtap.h>
#include <epan/frame_data.h>
#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/timestamp.h>
#include "cfile.h"

#include <glib.h>

#include "sharktools_frame_data.h"

void
frame_data_init(frame_data *fdata, guint32 num,
                const struct wtap_pkthdr *phdr, gint64 offset,
                guint32 cum_bytes)
{
  fdata->next = NULL;
  fdata->prev = NULL;
  fdata->pfd = NULL;
  fdata->num = num;
  fdata->pkt_len = phdr->len;
  fdata->cum_bytes = cum_bytes + phdr->len;
  fdata->cap_len = phdr->caplen;
  fdata->file_off = offset;
  /* To save some memory, we coerce it into a gint16 */
  g_assert(phdr->pkt_encap <= G_MAXINT16);
  fdata->lnk_t = (gint16) phdr->pkt_encap;
  fdata->abs_ts.secs = phdr->ts.secs;
  fdata->abs_ts.nsecs = phdr->ts.nsecs;
  fdata->flags.passed_dfilter = 0;
#if WIRESHARK_1_4_0
  fdata->flags.encoding = PACKET_CHAR_ENC_CHAR_ASCII;
#else
  fdata->flags.encoding = CHAR_ASCII;
#endif
  fdata->flags.visited = 0;
  fdata->flags.marked = 0;
  fdata->flags.ref_time = 0;
  //fdata->flags.ignored = 0;
  fdata->color_filter = NULL;
#ifdef NEW_PACKET_LIST
  fdata->col_text_len = NULL;
  fdata->col_text = NULL;
#endif
}

void
frame_data_set_before_dissect(frame_data *fdata,
                nstime_t *elapsed_time,
                nstime_t *first_ts,
                nstime_t *prev_dis_ts,
                nstime_t *prev_cap_ts)
{
  /* If we don't have the time stamp of the first packet in the
     capture, it's because this is the first packet.  Save the time
     stamp of this packet as the time stamp of the first packet. */
  if (nstime_is_unset(first_ts))
    *first_ts = fdata->abs_ts;

  /* if this frames is marked as a reference time frame, reset
     firstsec and firstusec to this frame */
  if(fdata->flags.ref_time)
    *first_ts = fdata->abs_ts;

  /* If we don't have the time stamp of the previous captured packet,
     it's because this is the first packet.  Save the time
     stamp of this packet as the time stamp of the previous captured
     packet. */
  if (nstime_is_unset(prev_cap_ts))
    *prev_cap_ts = fdata->abs_ts;

  /* Get the time elapsed between the first packet and this packet. */
  nstime_delta(&fdata->rel_ts, &fdata->abs_ts, first_ts);

  /* If it's greater than the current elapsed time, set the elapsed time
     to it (we check for "greater than" so as not to be confused by
     time moving backwards). */
  if ((gint32)elapsed_time->secs < fdata->rel_ts.secs
    || ((gint32)elapsed_time->secs == fdata->rel_ts.secs && (gint32)elapsed_time->nsecs < fdata->rel_ts.nsecs)) {
    *elapsed_time = fdata->rel_ts;
  }

  /* Get the time elapsed between the previous displayed packet and
     this packet. */
  if (nstime_is_unset(prev_dis_ts))
    /* If we don't have the time stamp of the previous displayed packet,
       it's because we have no displayed packets prior to this.
       Set the delta time to zero. */
    nstime_set_zero(&fdata->del_dis_ts);
  else
  nstime_delta(&fdata->del_dis_ts, &fdata->abs_ts, prev_dis_ts);

  /* Get the time elapsed between the previous captured packet and
     this packet. */
  nstime_delta(&fdata->del_cap_ts, &fdata->abs_ts, prev_cap_ts);
  *prev_cap_ts = fdata->abs_ts;
}

void
frame_data_set_after_dissect(frame_data *fdata,
                guint32 *cum_bytes,
                nstime_t *prev_dis_ts)
{
  /* This frame either passed the display filter list or is marked as
     a time reference frame.  All time reference frames are displayed
     even if they dont pass the display filter */
  if(fdata->flags.ref_time){
    /* if this was a TIME REF frame we should reset the cul bytes field */
    *cum_bytes = fdata->pkt_len;
    fdata->cum_bytes = *cum_bytes;
  } else {
    /* increase cum_bytes with this packets length */
    *cum_bytes += fdata->pkt_len;
    fdata->cum_bytes = *cum_bytes;
  }

  /* Set the time of the previous displayed frame to the time of this
     frame. */
  *prev_dis_ts = fdata->abs_ts;
}

void
frame_data_cleanup(frame_data *fdata)
{
  if (fdata->pfd)
    g_slist_free(fdata->pfd);

  fdata->pfd = NULL;
}

#endif //(WIRESHARK_0_99_5 || WIRESHARK_1_0_0 || WIRESHARK_1_2_0)

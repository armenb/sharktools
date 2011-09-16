/* frame_data.h
 * Definitions for frame_data structures and routines
 *
 * $Id: frame_data.h 33614 2010-07-22 09:14:24Z guy $
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

#ifndef __SHARKTOOLS_FRAME_DATA_H__
#define __SHARKTOOLS_FRAME_DATA_H__

extern void frame_data_cleanup(frame_data *fdata);

extern void frame_data_init(frame_data *fdata, guint32 num,
                const struct wtap_pkthdr *phdr, gint64 offset,
                guint32 cum_bytes);

extern void frame_data_set_before_dissect(frame_data *fdata,
                nstime_t *elapsed_time,
                nstime_t *first_ts,
                nstime_t *prev_dis_ts,
                nstime_t *prev_cap_ts);

extern void frame_data_set_after_dissect(frame_data *fdata,
                guint32 *cum_bytes,
                nstime_t *prev_dis_ts);

#endif  /* __SHARKTOOLS_FRAME_DATA__ */


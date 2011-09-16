/* epan.h
 *
 * $Id: epan.h 21716 2007-05-07 17:55:42Z gal $
 *
 * Wireshark Protocol Analyzer Library
 *
 * Copyright (c) 2001 by Gerald Combs <gerald@wireshark.org>
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

#ifndef SHARKTOOLS_EPAN_H
#define SHARKTOOLS_EPAN_H

#if 0
#include <glib.h>
#include <epan/frame_data.h>
#include <epan/column_info.h>
#include "register.h"

#include <epan/dfilter/dfilter.h>
#endif

#include <epan/epan.h>
#include <epan/epan_dissect.h>

/* initialize an existing single packet dissection */
epan_dissect_t*
epan_dissect_init(epan_dissect_t	*edt, const gboolean create_proto_tree, const gboolean proto_tree_visible);

void
epan_dissect_cleanup(epan_dissect_t* edt);

#endif /* SHARKTOOLS_EPAN_H */

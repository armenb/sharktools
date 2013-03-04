/* cfile.c
 * capture_file GUI-independent manipulation 
 * Vassilii Khachaturov <vassilii@tarunz.org>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdlib.h>

#include <glib.h>

#include <epan/packet.h>

#include "sharktools_cfile.h"

void
cap_file_init(capture_file *cf)
{
  /*
    Keeping this initialization routine
    updated across various versions of wireshark
    was a bit messy, and there really isn't any
    point to it, because everything gets set to 0
    besides the frame length
  */
  memset(cf, 0, sizeof(capture_file));
  cf->snap		= WTAP_MAX_PACKET_SIZE;
}

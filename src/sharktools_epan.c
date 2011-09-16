/* epan.c
 *
 * $Id: epan.c 33999 2010-08-29 17:19:24Z gerald $
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

/*
 * APB: this file contains several functions from wireshark-1.4.0/epan/epan.c 
 * that were backported to accomodate wireshark-0.99.5, 1.0.*, and 1.2.*
 *
 * We only want to include the content of this file if we are < 1.4.0 (or there
 * will be redefinitions)
 */
#if (WIRESHARK_0_99_5 || WIRESHARK_1_0_0 || WIRESHARK_1_2_0)

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <epan/packet.h> // for free_data_sources()

#include "sharktools_epan.h"

/* APB: from wireshark-1.4.0/epan/epan.c, backported for wireshark pre-1.4.0 support */
epan_dissect_t*
epan_dissect_init(epan_dissect_t	*edt, const gboolean create_proto_tree, const gboolean proto_tree_visible)
{
	g_assert(edt);

	if (create_proto_tree) {
		edt->tree = proto_tree_create_root();
		proto_tree_set_visible(edt->tree, proto_tree_visible);
	}
	else {
		edt->tree = NULL;
	}

	return edt;
}

/* APB: from wireshark-1.4.0/epan/epan.c, backported for wireshark pre-1.4.0 support */
void
epan_dissect_cleanup(epan_dissect_t* edt)
{
	g_assert(edt);

	/* Free the data sources list. */
	free_data_sources(&edt->pi);

	/* Free all tvb's created from this tvb, unless dissector
	 * wanted to store the pointer (in which case, the dissector
	 * would have incremented the usage count on that tvbuff_t*) */
	tvb_free_chain(edt->tvb);

	if (edt->tree) {
		proto_tree_free(edt->tree);
	}
}

#endif //(WIRESHARK_0_99_5 || WIRESHARK_1_0_0 || WIRESHARK_1_2_0)

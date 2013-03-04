/* Copyright (c) 2007-2011
 *      Massachusetts Institute of Technology
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
 * along with this program (see the file COPYING); if not, see
 * http://www.gnu.org/licenses/, or contact Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 ****************************************************************
 */

/* IN NO EVENT SHALL MIT BE LIABLE TO ANY PARTY FOR DIRECT, INDIRECT,
 * SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF
 * THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF MIT HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * MIT SPECIFICALLY DISCLAIMS ANY EXPRESS OR IMPLIED WARRANTIES INCLUDING,
 * BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT.
 *
 * MIT HAS NO OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES,
 * ENHANCEMENTS, OR MODIFICATIONS TO THIS SOFTWARE.
 */

/*
 * Sharktools Core
 *
 * Contact: Armen Babikyan, MIT Lincoln Laboratory, <armenb@mit.edu>
 */

#ifndef SHARKTOOLS_CORE_H
#define SHARKTOOLS_CORE_H

#include <stdio.h>
#include <glib.h>

#if WIRESHARK_1_8_0
#define WS_MSVC_NORETURN
#endif

#define WS_VAR_IMPORT extern
#include <epan/ftypes/ftypes.h>

#ifndef HAVE_STDARG_H
#define HAVE_STDARG_H /* for using stdarg.h instead of varargs.h */
#endif /* HAVE_STDARG_H */

/* APB: If we're running pre-1.4.0, include back-ported functions that are not
 * available pre-1.4.0
 */

#if (WIRESHARK_0_99_5 || WIRESHARK_1_0_0 || WIRESHARK_1_2_0)
#include "sharktools_epan.h"
#include "sharktools_frame_data.h"
#include "sharktools_cfile.h"
#endif /* (WIRESHARK_0_99_5 || WIRESHARK_1_0_0 || WIRESHARK_1_2_0) */

#if WIRESHARK_1_8_0
#include <epan/dfilter/dfilter.h>
#include <epan/frame_data.h>
#include <cfile.h>
#endif

typedef struct _ret_info {
  GPtrArray *values;
  GArray *types;
} ret_info;

typedef struct sharktools_callbacks {
  gpointer root;
  gpointer* keys;
  gulong count;
  gpointer (*row_new)(struct sharktools_callbacks *cb);
  /* gpointer (*row_set)(struct sharktools_callbacks *cb, gpointer row, gpointer key, gulong type, fvalue_t *val_native,  const gchar *val_string); */
  gpointer (*row_set)(struct sharktools_callbacks *cb, gpointer row, gpointer key, gulong type, GPtrArray* tree_values);
  gpointer (*row_add)(struct sharktools_callbacks *cb, gpointer row);
} sharktools_callbacks;

/**
 * This structure holds Sharktools-specific data that is routed through
 * libwireshark's callback system.
 * 
 * It is worth noting that fields and field_indices are calculated
 * once per execution of sharktools, while field_values and field_types
 * are updated once per packet processed.
 */
typedef struct _stdata_t
{
  capture_file cfile;

  gulong nfields;

  /**
   * 'fieldnames' holds an ordered list of keys (strings) that are field names
   * of interest, e.g. 'frame.number' or 'ip.len'
   * 'field_indicies' holds a mappings of hash(key) => integer, where the
   * integer describes the key's order in 'fields'.
   * (This is necessary to avoid lots of string compares later)
   */
  GPtrArray* fieldnames;
  GHashTable* field_indicies;

  GPtrArray* wfieldnames;

  /**
   * Arrays for fieldnames without wildcards in them
   * 
   * 'tree_values' holds an ordered list of values found for
   * a particular packet.
   * 'field_types' holds an ordered list of data types (enum, in
   * epan/ftypes/ftypes.h) for each respective value in 'field_values_str'
   *
   * NB: Using GPtrArrays instead of GHashTables here speeds up access time
   * because no time has to be spent generating the hash during a key lookup.
   */
  GPtrArray* tree_values;
  gulong *field_types; /* AB: added to original _output_fields datatype in print.c */
  GArray *tree_types;

  /* Hashtables for fieldnames with wildcards in them */
  GHashTable *wtree_values;
  GHashTable *wtree_types;


  gchar        *err_info;
  gint64       data_offset;


} st_data_t;

char sharktools_errmsg[2048];

st_data_t* stdata_new();
void stdata_free(st_data_t *stdata);

int sharktools_preload_libs(void);
void sharktools_register_native_types(GTree *native_types);
GCompareFunc sharktools_gulong_cmp(gconstpointer a, gconstpointer b);
int sharktools_init(void);
int sharktools_cleanup(void);
long sharktools_add_decode_as(char *s);
long sharktools_remove_decode_as(char *s);
long sharktools_count(char *filename, char *dfilter);

long sharktools_get_cb(gchar *filename, gulong nfields, const gchar **fields,
                       gchar *dfilter, sharktools_callbacks *cb);

glong sharktools_iter_init(st_data_t *stdata, gchar *filename, const gchar *dfilter);
gboolean sharktools_iter_next(st_data_t *stdata);
gint sharktools_iter_cleanup(st_data_t *stdata);


#endif /* SHARKTOOLS_CORE_H */

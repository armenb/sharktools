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

#include <stdio.h>
#include <glib.h>

#define WS_VAR_IMPORT extern
#include <epan/ftypes/ftypes.h>

typedef struct _ret_info {
  GPtrArray *values;
  GArray *types;
} ret_info;

typedef struct sharktools_callbacks {
  gpointer root;
  gpointer* keys;
  gulong count;
  gpointer (*row_new)(struct sharktools_callbacks *cb);
  gpointer (*row_set)(struct sharktools_callbacks *cb, gpointer row, gpointer key, gulong type, fvalue_t *val_native,  const gchar *val_string);
  gpointer (*row_add)(struct sharktools_callbacks *cb, gpointer row);
} sharktools_callbacks;

char sharktools_errmsg[2048];

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




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
#include <string.h>
#include <errno.h>

#include <assert.h>

/* wireshark headers */
//#define HAVE_STDARG_H /* for using stdarg.h instead of varargs.h */
#define WS_VAR_IMPORT extern
#include <config.h>
#include <file.h>
#include <epan/epan.h>
#include <epan/tap.h>
#include <epan/proto.h>
#include <epan/dfilter/dfilter.h>
#include <epan/epan_dissect.h>
#include <epan/filesystem.h>

#if WIRESHARK_0_99_5
#include <epan/emem.h>
#include <register.h>
#define ep_alloc_array0(type,num) (type*)ep_alloc0(sizeof(type)*(num))
#endif //WIRESHARK_0_99_5

#include <register.h>
#include <epan/plugins.h>

/* APB: wireshark >= 1.0 wants get_credential_info(), which is located in privileges.h
 */
#if WIRESHARK_1_0_0
#include <epan/privileges.h>
#elif (WIRESHARK_1_2_0 || WIRESHARK_1_4_0 || WIRESHARK_1_8_0 || WIRESHARK_1_10_0)
#include <wsutil/privileges.h>
#endif

#include "sharktools_core.h"

// Get the add_decode_as() functionality
#include "sharktools_add_decode_as.h"

/* APB: If we're running pre-1.4.0, include back-ported functions that are not
 * available pre-1.4.0
 */
#if (WIRESHARK_0_99_5 || WIRESHARK_1_0_0 || WIRESHARK_1_2_0)
#include "sharktools_epan.h"
#include "sharktools_frame_data.h"
#include "sharktools_cfile.h"
#endif //(WIRESHARK_0_99_5 || WIRESHARK_1_0_0 || WIRESHARK_1_2_0)

// Allow a -DDEBUG=0 to be passed to the compiler.
#ifndef DEBUG
#define DEBUG 1
#endif

#if DEBUG
#define dprintf(args...) printf(args)
#else
#define dprintf(args...) ((void)0)
#endif

/**
 * This structure exists solely because libwireshark's libraries have callback
 * mechanisms accept one argument for the user-specified function, and we want
 * both the stdata structure and the edt tree passed to our specified function.
 */
typedef struct
{
  st_data_t *stdata;
  epan_dissect_t *edt;
} stdata_edt_tuple_t;

static const gchar* get_node_field_value_as_string(field_info* fi, epan_dissect_t* edt);
void proto_tree_get_fields(st_data_t* stdata, epan_dissect_t *edt);
static void proto_tree_get_node_field_values(proto_node *node, gpointer data);
static const gchar* get_field_hex_value2(GSList* src_list, field_info *fi);
static const guint8 *get_field_data(GSList *src_list, field_info *fi);

gboolean process_packet(capture_file *cf, gint64 offset, st_data_t *stdata);

extern char sharktools_errmsg[2048];

#define errmsg sharktools_errmsg

long verbose = 1;
static guint32 cum_bytes = 0;

static nstime_t first_ts;

#ifdef WIRESHARK_1_10_0
static frame_data *prev_dis;
static frame_data prev_dis_frame;
static frame_data *prev_cap;
static frame_data prev_cap_frame;
#else
static nstime_t prev_dis_ts;
static nstime_t prev_cap_ts;
#endif

static const char *cf_open_error_message(int err, gchar *err_info, int file_type)
{
  const char *errmsg;
  static char errmsg_errno[1024+1];

  if (err < 0)
    {
      /* Wiretap error. */
      switch (err)
	{
	  
	case WTAP_ERR_NOT_REGULAR_FILE:
	  errmsg = "The file \"%s\" is a \"special file\" or socket or other non-regular file.";
	  break;
	  
	case WTAP_ERR_FILE_UNKNOWN_FORMAT:
	  /* Seen only when opening a capture file for reading. */
	  errmsg = "The file \"%s\" isn't a capture file in a format Sharktools understands.";
	  break;
	  
	case WTAP_ERR_UNSUPPORTED:
	  /* Seen only when opening a capture file for reading. */
	  g_snprintf(errmsg_errno, sizeof(errmsg_errno),
		     "The file \"%%s\" isn't a capture file in a format Sharktools understands.\n"
		     "(%s)", err_info);
	  g_free(err_info);
	  errmsg = errmsg_errno;
	  break;
	  
	case WTAP_ERR_CANT_WRITE_TO_PIPE:
	  /* Seen only when opening a capture file for writing. */
	  g_snprintf(errmsg_errno, sizeof(errmsg_errno),
		     "The file \"%%s\" is a pipe, and %s capture files can't be "
		     "written to a pipe.", wtap_file_type_string(file_type));
	  errmsg = errmsg_errno;
	  break;
	  
	case WTAP_ERR_UNSUPPORTED_FILE_TYPE:
	  /* Seen only when opening a capture file for writing. */
	  errmsg = "Sharktools doesn't support writing capture files in that format.";
	  break;
	  
	case WTAP_ERR_UNSUPPORTED_ENCAP:
	  g_snprintf(errmsg_errno, sizeof(errmsg_errno),
		     "The file \"%%s\" is a capture for a network type that Sharktools doesn't support.\n"
		     "(%s)", err_info);
	  g_free(err_info);
	  errmsg = errmsg_errno;
	  break;
	  
	case WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED:
	  errmsg = "The file \"%s\" is a capture for a network type that Sharktools doesn't support.";
	  break;
	  
#if  (defined(WIRESHARK_1_8_0) == 0) && (defined(WIRESHARK_1_10_0) == 0)
	case WTAP_ERR_BAD_RECORD:
	  /* Seen only when opening a capture file for reading. */
	  g_snprintf(errmsg_errno, sizeof(errmsg_errno),
		     "The file \"%%s\" appears to be damaged or corrupt.\n"
		     "(%s)", err_info);
	  g_free(err_info);
	  errmsg = errmsg_errno;
	  break;
#endif
	  
	case WTAP_ERR_CANT_OPEN:
	  errmsg = "The file \"%s\" could not be opened for some unknown reason.";
	  break;
	  
	case WTAP_ERR_SHORT_READ:
	  errmsg = "The file \"%s\" appears to have been cut short"
	    " in the middle of a packet or other data.";
	  break;
	  
	case WTAP_ERR_SHORT_WRITE:
	  errmsg = "A full header couldn't be written to the file \"%s\".";
	  break;
	  
	default:
	  g_snprintf(errmsg_errno, sizeof(errmsg_errno),
		     "The file \"%%s\" could not be opened: %s.",
		     wtap_strerror(err));
	  errmsg = errmsg_errno;
	  break;
	}
    }
  else
    // FALSE == for_writing == FALSE
    errmsg = file_open_error_message(err, FALSE);
  return errmsg;
}

cf_status_t cf_open(capture_file *cf, const char *fname, gboolean is_tempfile, int *err)
{
  wtap       *wth;
  gchar       *err_info;
  //char        err_msg[2048+1];

  dprintf("%s: fname =  %s\n", __FUNCTION__, fname);
  dprintf("%s: is_tempfile = %d  err = %p\n", __FUNCTION__, is_tempfile, err);
  wth = wtap_open_offline(fname, err, &err_info, FALSE);
  dprintf("wth = %p\n", wth);
  if (wth == NULL)
    goto fail;

  /* The open succeeded.  Fill in the information for this file. */

#if (WIRESHARK_1_4_0 || WIRESHARK_1_8_0)
  /* Cleanup all data structures used for dissection. */
  cleanup_dissection();
#endif

  /* Initialize all data structures used for dissection. */
  init_dissection();

  cf->wth = wth;
  cf->f_datalen = 0; /* not used, but set it anyway */

  /* Set the file name because we need it to set the follow stream filter.
     XXX - is that still true?  We need it for other reasons, though,
     in any case. */
  cf->filename = g_strdup(fname);

  /* Indicate whether it's a permanent or temporary file. */
  cf->is_tempfile = is_tempfile;

#if defined(WIRESHARK_1_8_0) || defined(WIRESHARK_1_10_0)
  /* No user changes yet. */
  cf->unsaved_changes = FALSE;
#else
  /* If it's a temporary capture buffer file, mark it as not saved. */
  cf->user_saved = !is_tempfile;
#endif

  cf->cd_t      = wtap_file_type(cf->wth);
  cf->count     = 0;
  cf->drops_known = FALSE;
  cf->drops     = 0;
  cf->snap      = wtap_snapshot_length(cf->wth);
  if (cf->snap == 0)
    {
      /* Snapshot length not known. */
      cf->has_snap = FALSE;
      cf->snap = WTAP_MAX_PACKET_SIZE;
    }
  else
    cf->has_snap = TRUE;
  nstime_set_zero(&cf->elapsed_time);
  nstime_set_unset(&first_ts);

#ifdef WIRESHARK_1_10_0
 prev_dis = NULL;
 prev_cap = NULL;
#else
  nstime_set_unset(&prev_dis_ts);
  nstime_set_unset(&prev_cap_ts);
#endif

#if WIRESHARK_1_4_0
  cf->state = FILE_READ_IN_PROGRESS;

 #if defined(WIRESHARK_1_8_0) || defined(WIRESHARK_1_10_0)
  wtap_set_cb_new_ipv4(cf->wth, add_ipv4_name);
  wtap_set_cb_new_ipv6(cf->wth, (wtap_new_ipv6_callback_t) add_ipv6_name);
 #endif
#endif

  dprintf("%s: exiting\n", __FUNCTION__);

  return CF_OK;

fail:
  g_snprintf(sharktools_errmsg, sizeof(sharktools_errmsg),
             cf_open_error_message(*err, err_info, cf->cd_t), fname);
  return CF_ERROR;
}

/*
 * Open/create errors are reported with an console message in Sharktools.
 */
static void open_failure_message(const char *filename, int err, gboolean for_writing)
{
  dprintf("sharktools: open error");
  //fprintf(stderr, file_open_error_message(err, FALSE), filename);
  dprintf("\n");
}

/*
 * General errors are reported with an console message in Sharktools.
 */
static void
failure_message(const char *msg_format, va_list ap)
{
  dprintf("sharktools: %s", __FUNCTION__);
  vfprintf(stderr, msg_format, ap);
  dprintf("\n");
}

/*
 * Read errors are reported with an console message in Sharktools.
 */
static void
read_failure_message(const char *filename, int err)
{
  dprintf("An error occurred while reading from the file \"%s\": %s.",
          filename, strerror(err));
}

#if (WIRESHARK_1_2_0 || WIRESHARK_1_4_0 || WIRESHARK_1_8_0 || WIRESHARK_1_10_0)
/*
 * Write errors are reported with an console message in Sharktools.
 */
static void
write_failure_message(const char *filename, int err)
{
  dprintf("An error occurred while writing to the file \"%s\": %s.",
          filename, strerror(err));
}
#endif //(WIRESHARK_1_2_0 || WIRESHARK_1_4_0 || WIRESHARK_1_8_0)

static void
stdata_init_old(st_data_t* stdata, gulong nfields)
{
  gsize i;

  //stdata->fields = NULL; /*Do lazy initialisation */
  //stdata->field_values_str = NULL;
  //stdata->field_types = NULL;

  stdata->fieldnames = g_ptr_array_new();
  //stdata->fields = g_ptr_array_sized_new(nfields);

  /**
   * Here, we initialize field_indicies to NULL.  After fields are filled in,
   * proto_tree_get_fields() will create and populate the hashtable.
   */
  //stdata->field_indicies = NULL;

  /* Prepare a lookup table from string abbreviation for field to its index. */
  stdata->field_indicies = g_hash_table_new(g_str_hash, g_str_equal);

  // APB: We use g_new() here. ep_alloc_array0() is the wrong function to use because
  // it only allocates for a single packet lifetime, as described in epan/emem.c
  //stdata.field_values_str = ep_alloc_array0(const gchar*, stdata.fields->len);
  //stdata.field_types = ep_alloc_array0(gulong, stdata.fields->len);

  /* Buffers to store types and values for each packet */
  stdata->tree_values = g_ptr_array_new();
  for(i = 0; i < nfields; i++)
    {
      g_ptr_array_add( stdata->tree_values, g_ptr_array_new() );
    }

  stdata->field_types = g_new(gulong, nfields);

}

st_data_t*
stdata_new()
{
  st_data_t *stdata;

  stdata = g_new0(st_data_t, 1);

  stdata->fieldnames = g_ptr_array_new();
  stdata->wfieldnames = g_ptr_array_new();

  return stdata;
}

void
stdata_free(st_data_t *stdata)
{
  if(stdata->fieldnames)
    g_ptr_array_free(stdata->fieldnames, FALSE);
  if(stdata->wfieldnames)
    g_ptr_array_free(stdata->wfieldnames, FALSE);
  g_free(stdata);
}

static void
stdata_init(st_data_t* stdata)
{
  gsize i;

  // NB: fieldnames is *already* initialized by our caller
  gulong nfields = stdata->fieldnames->len;

  /* Prepare a lookup table from string abbreviation for field to its index. */
  stdata->field_indicies = g_hash_table_new(g_str_hash, g_str_equal);

  // APB: We use g_new() here. ep_alloc_array0() is the wrong function to use because
  // it only allocates for a single packet lifetime, as described in epan/emem.c

  /* Buffers to store types and values for each packet */
  stdata->tree_values = g_ptr_array_new();
  for(i = 0; i < nfields; i++)
    {
      g_ptr_array_add( stdata->tree_values, g_ptr_array_new() );
    }
  stdata->field_types = g_new(gulong, nfields);
  ////stdata->tree_types = g_array_sized_new(FALSE, TRUE, sizeof(gulong), nfields);

  stdata->wtree_types = g_hash_table_new(g_str_hash, g_str_equal);
  stdata->wtree_values = g_hash_table_new(g_str_hash, g_str_equal);

}

/**
 * Here we cleanup stdata by deallocating it's members in reverse order of
 * allocation.
 */
#if 0
static void
stdata_cleanup_old(st_data_t* stdata)
{
  gsize i;

  g_assert(stdata);
  
  ////g_array_free(stdata->tree_types, FALSE);

  g_free(stdata->field_types);

  for(i = 0; i < stdata->fieldnames->len; i++)
    {
      g_ptr_array_free( g_ptr_array_index(stdata->tree_values, i), TRUE);
     }
  g_ptr_array_free( stdata->tree_values, TRUE);
 

  if(NULL != stdata->field_indicies)
    {
      /* Keys are stored in stdata->fields, values are
       * integers.
       */
      g_hash_table_destroy(stdata->field_indicies);
    }

  for(i = 0; i < stdata->fieldnames->len; ++i)
    {
      gchar* field = g_ptr_array_index(stdata->fieldnames, i);
      g_free(field);
    }

  g_ptr_array_free(stdata->fieldnames, TRUE);


}
#endif

/**
 * Here we cleanup stdata by deallocating it's members in reverse order of
 * allocation.
 */
static void
stdata_cleanup(st_data_t* stdata)
{
  gsize i;

  g_assert(stdata);
  
  ////if(stdata->tree_types)
    ////g_array_free(stdata->tree_types, FALSE);

  if(stdata->field_types)
    g_free(stdata->field_types);


  if(stdata->tree_values)
    {
      for(i = 0; i < stdata->fieldnames->len; i++)
        {
          g_ptr_array_free( g_ptr_array_index(stdata->tree_values, i), TRUE);
        }
      g_ptr_array_free( stdata->tree_values, TRUE);
    }

  if(stdata->field_indicies)
    {
      /* Keys are stored in stdata->fields, values are
       * integers.
       */
      g_hash_table_destroy(stdata->field_indicies);
    }


  /*
  for(i = 0; i < stdata->fields->len; ++i)
    {
      gchar* field = g_ptr_array_index(stdata->fields,i);
      g_free(field);
    }
  */
}

/**
 * This function adds <fields> to the stdata data structure:  it copies the strings directly,
 * and it sets up the field_indicies hashtable.
 */
static void stdata_add_fields(st_data_t* stdata, const gchar** fields, gsize nfields)
{
  gsize i;

  g_assert(stdata);
  g_assert(fields);
  
  for(i = 0; i < nfields; i++)
    {
      dprintf("adding outputfield: %s\n", fields[i]);
      //stdata_add(&stdata, fields[i]);
      gchar* field_copy;
  
      field_copy = g_strdup(fields[i]);
  
      // Add to fields
      g_ptr_array_add(stdata->fieldnames, field_copy);

      // Add to hashtable
      g_hash_table_insert(stdata->field_indicies, field_copy, (gulong *)(i));
    }


#if 0
  for(i = 0; i < stdata->fields->len; i++)
    {
      gchar* field = g_ptr_array_index(stdata->fields, i);
      g_hash_table_insert(stdata->field_indicies, field, (gulong *)(i));
    }
#endif

}

static void compute_hashes_from_fieldnames(GHashTable *fieldname_indicies, const GPtrArray* fieldnames)
{
  gsize i;

  g_assert(fieldname_indicies);
  g_assert(fieldnames);
  
  for(i = 0; i < fieldnames->len; i++)
    {
      //dprintf("adding outputfield: %s\n", fieldnames[i]);
      //stdata_add(&stdata, fields[i]);
      gpointer fieldname = g_ptr_array_index(fieldnames, i);

      // Add to hashtable
      g_hash_table_insert(fieldname_indicies, fieldname, (gulong *)(i));
    }
}

static const guint8 *get_field_data(GSList *src_list, field_info *fi)
{
  GSList *src_le;
#ifdef WIRESHARK_1_10_0
  struct data_source *src;
#else
  data_source *src;
#endif
  tvbuff_t *src_tvb;
  gint length, tvbuff_length;
  
  for (src_le = src_list; src_le != NULL; src_le = src_le->next)
    {
      src = src_le->data;
#ifdef WIRESHARK_1_10_0
      src_tvb = get_data_source_tvb(src);
#else
      src_tvb = src->tvb;
#endif
      if (fi->ds_tvb == src_tvb)
	{
	  /*
	   * Found it.
	   *
	   * XXX - a field can have a length that runs past
	   * the end of the tvbuff.  Ideally, that should
	   * be fixed when adding an item to the protocol
	   * tree, but checking the length when doing
	   * that could be expensive.  Until we fix that,
	   * we'll do the check here.
	   */
	  tvbuff_length = tvb_length_remaining(src_tvb,
					       fi->start);
	  if (tvbuff_length < 0)
	    {
	      return NULL;
	    }
	  length = fi->length;
	  if (length > tvbuff_length)
	    length = tvbuff_length;
	  return tvb_get_ptr(src_tvb, fi->start, length);
	}
    }
  g_assert_not_reached();
  return NULL;	/* not found */
}

/**
 * Yeah, yeah, globals are bad
 */
GTree *G_native_types;

/**
 * Looks up type in the global G_native_types tree
 * 
 * @return True or False indication of search
 */
static inline gboolean is_native_type(gulong type)
{
  gboolean ret;

  if(G_native_types == NULL)
    {
      ret = FALSE;
    }
  else
    {
      if(g_tree_lookup(G_native_types, (gpointer)type) == NULL)
        {
          ret = FALSE;
        }
      else
        {
          ret = TRUE;
        }
    }

  dprintf("%s: type = %ld, ret = %d\n", __FUNCTION__, type, ret);
  return ret;
}

/**
 * This function is called for each node on the dissector tree, for a each packet,
 * First, this function sees if this node is one of the keys (e.g. 'frame.number')
 * we are looking for (nodes store the key in PITEM_FINFO(node)->hfinfo->abbrev).
 * If we found an appropriate field, copy the native value or string representation
 * of the value as appropriate.
 * 
 * Finally, recurse on child nodes.
 */
static void proto_tree_get_node_field_values(proto_node *node, gpointer data)
{
  stdata_edt_tuple_t *args = data;
  st_data_t *stdata = args->stdata;
  field_info	*fi;
  gpointer field_index;
  gpointer orig_key;
  gboolean key_found;
  gboolean is_wildcard_field = FALSE;

  fi = PITEM_FINFO(node);

  const gchar *key_str = fi->hfinfo->abbrev;  // e.g. char* that has, e.g., "ip.dst" or "frame.number"
  gpointer key = (gpointer)key_str;
  gulong type = fi->hfinfo->type;     // e.g. int that has, e.g., FT_UINT32 or FT_DOUBLE

  key_found = g_hash_table_lookup_extended(stdata->field_indicies,
                                           key,
                                           &orig_key,
                                           &field_index);
  
  if(!key_found)
    {
      // Look to see if the current field name matches any wildcards we have
      gint i;
      GPtrArray *wfieldnames = stdata->wfieldnames;
      for(i = 0; i < wfieldnames->len; i++)
        {
          if(g_str_has_prefix(key, g_ptr_array_index(wfieldnames, i)))
            {
              // Key found!
              key_found = TRUE;
              is_wildcard_field = TRUE;
              break;
            }
        }
    }
  
  gchar* val_str;
  gulong actual_index = (gulong)(field_index);

  if(key_found)
    {
      GPtrArray *values = NULL;

      dprintf("fi->hfinfo->abbrev = %s\n", fi->hfinfo->abbrev);

      /*
        XXX needs cleanup
        NB: wildcard and non-wildcard values and types get stored differently; each non-wildcard
        value/type get stored in arrays, wildcard value/type entries in hashtables.
        This is done for efficiency; hashing keys can get expensive - why bother hashing if
        we know the keys already (in the non-wildcard case)
        This next if/else block takes care of providing a "common" access mechanism to the
        values array.  Type access must be done manually.
      */
      if(is_wildcard_field)
        {
          values = g_hash_table_lookup(stdata->wtree_values, key);
          if(!values)
            {
              values = g_ptr_array_new();
              g_hash_table_insert(stdata->wtree_values, key, values);
              
              // NB: Assume all values have the same type; we set this on the first entry
              // dprintf("ty2pe: %d\n", type);

              // NB: type (a gulong) is being cast as a gpointer here.  This assumes
              // that gulongs are smaller-than or equal-to the size of gpointers.
              g_hash_table_insert(stdata->wtree_types, key, (gpointer)type);
            }
        }
      else
        {
          values = g_ptr_array_index(stdata->tree_values, actual_index);

          // NB: non-wildcard field type info is handled later in this fn...
        }
      
      if(type == FT_STRING)
        {
          dprintf("found a string!\n");
          dprintf("string is: %s\n", (char*)fvalue_get(&(fi->value)));
          dprintf("string as gnfvas: %s\n", get_node_field_value_as_string(fi, args->edt));

          val_str = (gchar *)get_node_field_value_as_string(fi, args->edt);

          g_ptr_array_add(values, val_str);
        }

      if(type == FT_NONE)
        {
          gulong tmp_type = FT_NONE;

          //check repr
          if(  fi->rep ){
            val_str = g_strdup( fi->rep->representation );

            g_ptr_array_add(values, val_str);
            
            tmp_type = FT_STRING;
          }

          if(is_wildcard_field)
            {
              //XXX CLEANUP
              //gulong *tmp2 = g_new0(gulong, 1);
              //*tmp2 = tmp_type;
              // NB: overwrite the previous value
              g_hash_table_insert(stdata->wtree_types, key, (gpointer)tmp_type);
            }
          else
            {
              stdata->field_types[actual_index] = tmp_type;
              ////g_array_insert_val(stdata->tree_types, actual_index, tmp_type);
            }
        }
      else if(is_native_type(type) == TRUE)
        {
          fvalue_t* tmp = g_new(fvalue_t,1);
          memcpy(tmp, &(fi->value), sizeof(fvalue_t));
          
          g_ptr_array_add(values, tmp);

          if(is_wildcard_field)
            {
              // already taken care of...
            }
          else
            {
              // If we can natively store the type,
              // do that and don't convert to a string
              stdata->field_types[actual_index] = type;
              ////g_array_insert_val(stdata->tree_types, actual_index, type);
            }
        }
      else
        {
          // As a last ditch options, convert the value to a string,
          // and don't bother storing the native type
          val_str = (gchar *)get_node_field_value_as_string(fi, args->edt);
          if(strlen(val_str) > 0)
            {
              if(is_wildcard_field)
                {
                  g_hash_table_insert(stdata->wtree_types, key, (gpointer)FT_STRING);
                }
              else
                {
                  gulong tmp_type = FT_STRING;
                  stdata->field_types[actual_index] = tmp_type;
                  ////g_array_insert_val(stdata->tree_types, actual_index, tmp_type);
                }
            }
          else
            {
              if(is_wildcard_field)
                {
                  g_hash_table_insert(stdata->wtree_types, key, (gpointer)type);
                }
              else
                {
                  stdata->field_types[actual_index] = type;
                  ////g_array_insert_val(stdata->tree_types, actual_index, type);
                }
            }
          g_ptr_array_add(values, val_str);
        }
    }

  /* Recurse here. */
  if (node->first_child != NULL)
    {
      proto_tree_children_foreach(node,
				  proto_tree_get_node_field_values, args);
    }
}

/* Returns an ep_alloced string or a static constant*/
static const gchar* get_node_field_value_as_string(field_info* fi, epan_dissect_t* edt)
{
  /* Text label. */
  if (fi->hfinfo->id == hf_text_only)
    {
      /* Get the text */
      if (fi->rep)
	{
	  return fi->rep->representation;
	}
      else
	{
          // XXX APB do we get here or later in this function?
	  return get_field_hex_value2(edt->pi.data_src, fi);
	}
    }
#if 0
  /* Uninterpreted data, i.e., the "Data" protocol, is
   * printed as a field instead of a protocol. */
  else if (fi->hfinfo->id == proto_data)
    {
      return get_field_hex_value2(edt->pi.data_src, fi);
    }
#endif  
  /* Normal protocols and fields */
  else
    {
      gchar		*dfilter_string;
      gint		chop_len;
      
      switch (fi->hfinfo->type)
	{
	case FT_NONE:
	  return NULL;
	case FT_PROTOCOL:
	  /* Print out the full details for the protocol. */
	  if (fi->rep)
	    {
	      return fi->rep->representation;
	    }
	  else
	    {
	      /* Just print out the protocol abbreviation */
	      //return fi->hfinfo->abbrev;;
        /* HACK - get the hex values - more useful than the abbrev */
	      return get_field_hex_value2(edt->pi.data_src, fi);
	    }
	default:
	  /* XXX - this is a hack until we can just call
	   * fvalue_to_string_repr() for *all* FT_* types. */
	  dfilter_string = proto_construct_match_selected_string(fi,
								 edt);
	  if (dfilter_string != NULL)
	    {
	      chop_len = strlen(fi->hfinfo->abbrev) + 4; /* for " == " */
	      
	      /* XXX - Remove double-quotes. Again, once we
	       * can call fvalue_to_string_repr(), we can
	       * ask it not to produce the version for
	       * display-filters, and thus, no
	       * double-quotes. */
	      if (dfilter_string[strlen(dfilter_string)-1] == '"')
		{
		  dfilter_string[strlen(dfilter_string)-1] = '\0';
		  chop_len++;
		}
	      
	      return &(dfilter_string[chop_len]);
	    }
	  else
	    {
	      return get_field_hex_value2(edt->pi.data_src, fi);
	    }
	}
    }
}

/* this function should be unnecessary - we don't want to convert values to hex. */
static const gchar* get_field_hex_value2(GSList* src_list, field_info *fi)
{
  const guint8 *pd;
  
  if (fi->length > tvb_length_remaining(fi->ds_tvb, fi->start))
    {
      return "field length invalid!";
    }
  
  /* Find the data for this field. */
  pd = get_field_data(src_list, fi);
  
  if (pd)
    {
      int i;
      gchar* buffer;
      gchar* p;
      int len;
      const int chars_per_byte = 2;
      
      len = chars_per_byte * fi->length;
      buffer = ep_alloc_array(gchar, len + 1);
      buffer[len] = '\0'; /* Ensure NULL termination in bad cases */
      p = buffer;
      /* Print a simple hex dump */
      for (i = 0 ; i < fi->length; i++)
	{
	  g_snprintf(p, len, "%02x", pd[i]);
	  p += chars_per_byte;
	  len -= chars_per_byte;
	}
      return buffer;
    }
  else
    {
      return NULL;
    }
}

/**
 * This function gets all field values for a packet.  It does this by
 * Creating a data structure to pass to libwireshark's
 * proto_tree_children_foreach(), which subsequently recursively traverses
 * the dissector tree.
 *
 * @param stdata Sharktools data structure,
 * @param edt dissector tree
 */
void proto_tree_get_fields(st_data_t* stdata, epan_dissect_t *edt)
{
  g_assert(stdata);
  g_assert(edt);
  
  stdata_edt_tuple_t arg;
  arg.stdata = stdata;
  arg.edt = edt;  
  
  proto_tree_children_foreach(edt->tree,
                              proto_tree_get_node_field_values,
			      &arg);
}

/**
 * Given a handle on a capture file, and an offset within that file,
 * this function will read a packet and decide if it matches the display
 * filter.  If it does, it calls proto_tree_get_fields() to read specific fields
 * into stdata.
 * 
 * @return passed a boolean describing whether the packet matched the filter.
 */
gboolean process_packet(capture_file *cf, gint64 offset, st_data_t *stdata)
{
  frame_data fdata;
  epan_dissect_t edt;
  gboolean passed;

#ifdef WIRESHARK_1_10_0
  struct wtap_pkthdr *whdr = wtap_phdr(cf->wth);
#else
  const struct wtap_pkthdr *whdr = wtap_phdr(cf->wth);
  union wtap_pseudo_header *pseudo_header = wtap_pseudoheader(cf->wth);
#endif
  const guchar *pd = wtap_buf_ptr(cf->wth);

  /* Count this packet.
     NB: the frame dissector uses this to determine frame.number
  */
  cf->count++;

  frame_data_init(&fdata, cf->count, whdr, offset, cum_bytes);

  /**
   * Initialize dissector tree
   */
  epan_dissect_init(&edt, TRUE, TRUE);

#ifdef WIRESHARK_1_10_0
  col_custom_prime_edt(&edt, &cf->cinfo);
  frame_data_set_before_dissect(&fdata, &cf->elapsed_time,
                                &first_ts, prev_dis, prev_cap);
#else
  frame_data_set_before_dissect(&fdata, &cf->elapsed_time,
                                &first_ts, &prev_dis_ts, &prev_cap_ts);
#endif

  passed = TRUE;

  // AB: prime the epan_dissect_t with the dfilter.
  if(cf->rfcode) {
    epan_dissect_prime_dfilter(&edt, cf->rfcode);
  }

#ifndef WIRESHARK_1_10_0
  tap_queue_init(&edt);
#endif

  /**
   * Run the dissector on this packet
   */
#ifdef WIRESHARK_1_10_0
  epan_dissect_run_with_taps(&edt, whdr, pd, &fdata, &cf->cinfo);
#else
  epan_dissect_run(&edt, pseudo_header, pd, &fdata, NULL);
#endif

#ifndef WIRESHARK_1_10_0
  tap_push_tapped_queue(&edt);
#endif
  
  // AB: Run the read filter
  if(cf->rfcode) {
    passed = dfilter_apply_edt(cf->rfcode, &edt);
  }
  else {
    passed = TRUE;
  }

  if(passed) {
#ifdef WIRESHARK_1_10_0
    frame_data_set_after_dissect(&fdata, &cum_bytes);
    prev_dis_frame = fdata;
    prev_dis = &prev_dis_frame;
    prev_cap_frame = fdata;
    prev_cap = &prev_cap_frame;
#else
    frame_data_set_after_dissect(&fdata, &cum_bytes, &prev_dis_ts);
#endif
    
    /* stdata could be NULL if we are just counting packets */
    if(stdata != NULL)
      proto_tree_get_fields(stdata, &edt);
  }

  epan_dissect_cleanup(&edt);
#ifdef WIRESHARK_1_10_0
  frame_data_destroy(&fdata);
#else
  frame_data_cleanup(&fdata);
#endif

  return passed;
}

/**
 * XXX: This was added to combat a problem where a dynamic linking error would occur
 * because some wireshark dissectors (i.e. libraries) did not dynamically link to
 * libwireshark and libglib-2.0.so, but required functions in them to be loaded.
 * 
 * This is hacky, and this function might not even be necessary in all configurations.
 */
int sharktools_preload_libs(void)
{

#define LIBWIRESHARK "libwireshark.so"
#define LIBGLIB "libglib-2.0.so"

  int ret = 0;

  GModule* handle;
  handle = g_module_open(LIBWIRESHARK, 0);
  if(!handle)
    {
      dprintf("%s", g_module_error());
      ret = 1;
    }

  GModule *handle2;
  handle2 = g_module_open(LIBGLIB, 0);
  if(!handle2)
    {
      dprintf("%s", g_module_error());
      ret = 1;
    }

  // XXX fixme: don't lose the handles and close the dynamic libs later (?)
  return ret;
}

/**
 * Registers a GTree of FT_* values that can be translated into native types
 * by the calling language.
 *
 * This is done to save unnecessary processing involved in converting
 * values to and from strings
 *
 * Note: must be called AFTER sharktools_init()
 */
void sharktools_register_native_types(GTree *_native_types)
{
  // NB: native_types_hash is a global variable
  G_native_types = _native_types;
}

GCompareFunc sharktools_gulong_cmp(gconstpointer a, gconstpointer b)
{
  gulong x1;
  gulong x2;
  x1 = (gulong)a;
  x2 = (gulong)b;

  return (gpointer)(x1 - x2);
}

/**
 * Sharktools Initialization
 * 
 * This function will subsequently initialize Wireshark and associated mechanisms.
 */
int sharktools_init(void)
{
  // NOTE: VERSION is a #define from config.h.  examples: "0.99.7" or "1.0.8"
  if(strcmp(epan_get_version(), VERSION)) {
    printf("ERROR: sharktools was compiled using version %s of libwireshark.\n", VERSION);
    printf("However, the libwireshark installed on this system is version %s.\n", epan_get_version());
    printf("Please recompile sharktools with headers from libwireshark version %s,\n", epan_get_version());
    printf("or modify LD_LIBRARY_PATH to point to version %s of libwireshark.\n", VERSION);
    printf("Consult sharktools' README file for more information on using a different version of libwireshark.\n");
    return -1;
  }

  // FIXME: Hacky; see note above.
  sharktools_preload_libs();

  /*
   * Get credential information for later use.
   */
#if (WIRESHARK_1_0_0 || WIRESHARK_1_2_0 || WIRESHARK_1_4_0)
  get_credential_info();
#elif defined(WIRESHARK_1_8_0) || defined(WIRESHARK_1_10_0)
  init_process_policies();
#endif
  
  dprintf("%s: initializing...\n", __FUNCTION__);
  
#if WIRESHARK_0_99_5
  epan_init(register_all_protocols, register_all_protocol_handoffs,
            failure_message, open_failure_message, read_failure_message);
#elif WIRESHARK_1_0_0
  epan_init(register_all_protocols, register_all_protocol_handoffs, NULL, NULL,
            failure_message, open_failure_message, read_failure_message);
#elif (WIRESHARK_1_2_0 || WIRESHARK_1_4_0 || WIRESHARK_1_8_0 || WIRESHARK_1_10_0)
  epan_init(register_all_protocols, register_all_protocol_handoffs, NULL, NULL,
            failure_message, open_failure_message, read_failure_message, write_failure_message);
#endif
  
  //register_all_plugin_tap_listeners();  
  //register_all_tap_listeners();

  // Set this global variable to NULL
  G_native_types = NULL;
  
  dprintf("%s: initialized.\n", __FUNCTION__);

  return 0;
}

/**
 * Ideally, this effectively un-does operations in sharktools_init()
 */
int sharktools_cleanup(void)
{
  dprintf("%s: called\n", __FUNCTION__);

  epan_cleanup();
  return 0;
}

/**
 * Adds a decode_as string to the wireshark engine
 */
long sharktools_add_decode_as(char *s)
{
  dprintf("%s: called\n", __FUNCTION__);

  /*
  int status;
  status = add_decode_as("udp.port==60000,aodv");
  if(!status)
    dprintf("add_decode_as failed.\n");
  */

  return add_decode_as(s);
}

/**
 * Removes a decode_as string from the wireshark engine
 */
long sharktools_remove_decode_as(char *s)
{
  dprintf("%s: called\n", __FUNCTION__);

  return remove_decode_as(s);
}

/**
 * This function returns the number of packets in <filename> that would
 * pass through the filter <dfilter>.  This was necessary to mitigate memory
 * usage in Matlab, where dynamically-growing or shrinking data structures
 * (apparently) don't exist.  If it looks hacky, it is :-)
 *
 * NB: there is a race condition between running sharktools_count() and
 * sharktools_get_cb(), since we close and reopen the pcap file in between.
 */
glong sharktools_count(char *filename, char *dfilter)
{
  capture_file cfile;
  gchar *cf_name = NULL;
  dfilter_t *rfcode = NULL;
  glong count = 0;

  dprintf("%s: entering...\n", __FUNCTION__);

  dprintf("%s: dfilter: %s\n", __FUNCTION__, dfilter);
  if(!dfilter_compile(dfilter, &rfcode))
    {
      sprintf(errmsg, "%s", dfilter_error_msg);
      printf("errmsg");
      if(rfcode)
        dfilter_free(rfcode);
      return -1;
    }

  // Defined in cfile.c, looks easy enough to use
  cap_file_init(&cfile);

  cf_name = filename;

  // Open pcap file
  int err;
  if(cf_open(&cfile, cf_name, FALSE, &err) != CF_OK)
    {
      //sprintf(errmsg, "%s", dfilter_error_msg);
      if(rfcode)
        dfilter_free(rfcode);
      return -1;
    }

  dprintf("%s: opened file\n", __FUNCTION__);

  cfile.rfcode = rfcode;

  gchar        *err_info;
  gint64       data_offset;

  // Read and process each packet one at a time
  while(wtap_read(cfile.wth, &err, &err_info, &data_offset))
    {
      gboolean passed = TRUE;
      
      // Only process packets if there's a display filter specified
      if(dfilter != NULL && *dfilter != '\0')
        {
          // Passing in NULL for st_data_t means we're just counting
          passed = process_packet(&cfile, data_offset, NULL);
        }

      if(passed)
	{
          count++;
          //dprintf("count! %d\n", count);
        }
    }

  if(rfcode)
    dfilter_free(rfcode);
  wtap_close(cfile.wth);
  cfile.wth = NULL;

  return count;
}

/**
 * This function processes a specified capture file with the specified fields of interest
 * and display filter.  This function calls the appropriate language-specific callback
 * function in <cb> to manipulate data structures in the caller's scope.
 * 
 * @param filename valid pcap file
 * @param nfields a positive integer describing the number of fields
 * @param fields an array of strings
 * @return 0 on success, else error.
 */
glong sharktools_get_cb(gchar *filename, gulong nfields, const gchar **fields,
                       gchar *dfilterorig, sharktools_callbacks *cb)
{
  gsize i;
  capture_file cfile;
  gchar *cf_name = NULL;
  char *dfilter;
  dfilter_t *rfcode = NULL;

  // Create an stdata struct on the stack
  st_data_t stdata;

  dprintf("%s: entering...\n", __FUNCTION__);

  dprintf("%s: dfilterorig: %s\n", __FUNCTION__, dfilterorig);

  dfilter = strdup(dfilterorig);

  dprintf("%s: dfilter: %s\n", __FUNCTION__, dfilter);

  if(!dfilter_compile(dfilter, &rfcode))
    {
      sprintf(errmsg, "%s", dfilter_error_msg);
      printf("errmsg");
      if(rfcode)
        dfilter_free(rfcode);
      return -1;
    }

  // Defined in cfile.c, looks easy enough to use
  cap_file_init(&cfile);

  cf_name = filename;

  // Open pcap file
  int err;
  if(cf_open(&cfile, cf_name, FALSE, &err) != CF_OK)
    {
      //sprintf(errmsg, "%s", dfilter_error_msg);
      if(rfcode)
        dfilter_free(rfcode);
      return -1;
    }

  dprintf("nfields = %ld\n", nfields);

  stdata_init_old(&stdata, nfields);

  stdata_add_fields(&stdata, fields, nfields);

  dprintf("stdata.fieldnames->len = %d\n", stdata.fieldnames->len);

  dprintf("stdata.field_types = %p\n", stdata.field_types);
  
  dprintf("%s: opened file\n", __FUNCTION__);

  cfile.rfcode = rfcode;

  gchar        *err_info;
  gint64       data_offset;

  // Read and process each packet one at a time
  while(wtap_read(cfile.wth, &err, &err_info, &data_offset))
    {
      //dprintf("*******************************\n");

      // (Re)-set all the stdata.field_{values,types} fields
      for(i = 0; i < nfields; i++)
        {
          stdata.field_types[i] = FT_NONE;
        }

      gboolean passed = FALSE;
      
      passed = process_packet(&cfile, data_offset, &stdata);

      if(passed)
	{
          gpointer row = cb->row_new(cb);

	  for(i = 0; i < nfields; i++)
	    {
              gpointer key;
              key = cb->keys[i];

              //dprintf("key = %p\n", key);

	      //dprintf("types[%ld] = %ld\n", i, stdata.field_types[i]);

              cb->row_set(cb, row, key,
                          stdata.field_types[i],
                          g_ptr_array_index( stdata.tree_values, i)
                          );
            }

          cb->row_add(cb, row);
          //reset tree_values
          g_ptr_array_free( stdata.tree_values, TRUE);
          stdata.tree_values = g_ptr_array_new();
          for(i = 0; i < nfields; i++)
            {
              g_ptr_array_add( stdata.tree_values, g_ptr_array_new() );
            }

        }
    }

  if(rfcode)
    dfilter_free(rfcode);
  wtap_close(cfile.wth);
  cfile.wth = NULL;

  stdata_cleanup(&stdata);

  dprintf("%s: ...leaving.\n", __FUNCTION__);

  return 0;
}

/* Functions to use for languages that natively support iterators (e.g. Python) */

glong
sharktools_iter_init(st_data_t *stdata, gchar *filename, const gchar *dfilter)
{
  gchar *cf_name = NULL;
  dfilter_t *rfcode = NULL;
  capture_file *cf;


#ifdef WIRESHARK_1_10_0
  char                *gpf_path, *pf_path;
  int                  gpf_open_errno, gpf_read_errno;
  int                  pf_open_errno, pf_read_errno;
#endif


  dprintf("%s: entering...\n", __FUNCTION__);

  stdata_init(stdata);

  compute_hashes_from_fieldnames(stdata->field_indicies, stdata->fieldnames);

  dprintf("stdata->fieldnames->len = %d\n", stdata->fieldnames->len);

  dprintf("stdata->field_types = %p\n", stdata->field_types);
  
  dprintf("%s: dfilter: %s\n", __FUNCTION__, dfilter);

  if(!dfilter_compile(dfilter, &rfcode)) {
    sprintf(errmsg, "%s", dfilter_error_msg);
    if(rfcode)
      dfilter_free(rfcode);
    return -1;
  }

  cf = &(stdata->cfile);

  /* Defined in cfile.c, looks easy enough to use */
  cap_file_init(cf);

  cf_name = filename;

#ifdef WIRESHARK_1_10_0
  read_prefs(&gpf_open_errno, &gpf_read_errno, &gpf_path,
          &pf_open_errno, &pf_read_errno, &pf_path);
#endif

  /* Open pcap file */
  int err;
  if(cf_open(cf, cf_name, FALSE, &err) != CF_OK) {
    //sprintf(errmsg, "%s", dfilter_error_msg);
    if(rfcode)
      dfilter_free(rfcode);
    return -1;
  }

  /* NB: cap_file_init or cf_open zero out cf->rfcode, so
     change it after those operations
  */
  cf->rfcode = rfcode;

#ifdef WIRESHARK_1_10_0
  build_column_format_array(&cf->cinfo, stdata->nfields, TRUE);
#endif

  dprintf("%s: opened file\n", __FUNCTION__);

  return 0;
}


gboolean
sharktools_iter_next(st_data_t *stdata)
{
  /*
    Continue reading the file to find a matched packet
    or else return something signifying that we're done
    (e.g. something that translates into StopIteration exception in Python
  */
  capture_file *cf = &(stdata->cfile);

  // Read and process each packet one at a time
  int err; // XXX useful??
  while(wtap_read(cf->wth, &err, &(stdata->err_info), &(stdata->data_offset))) {
    //dprintf("*******************************\n");
    
    // (Re)-set all the stdata->field_{values,types} fields
    // FIXME: does this actually need to be done?
    int i;
    for(i = 0; i < stdata->fieldnames->len; i++) {
      stdata->field_types[i] = FT_NONE;
    }
    
    gboolean passed = FALSE;
    
    passed = process_packet(cf, stdata->data_offset, stdata);
    
    if(passed) {
      /*
        NB: If passed is true, then stdata->field_{types,values_native,values_str}
        contain a matched packet's data
        by returning 1, we let our calling environment know there's data
        for it to read.
      */
      return TRUE;
    }
    
  }

  /* Something signifying a that the iteration is done */
  return FALSE;
}

gint
sharktools_iter_cleanup(st_data_t *stdata)
{
  capture_file *cf = &(stdata->cfile);
  if(cf->rfcode)
    dfilter_free(cf->rfcode);
  if(cf->wth) {
    wtap_close(cf->wth);
    cf->wth = NULL;
  }
  
  stdata_cleanup(stdata);

  dprintf("%s: ...leaving.\n", __FUNCTION__);

  return 0;
}

/////////////////////////////////////////////////////////////////////////////////
// Cruft
/////////////////////////////////////////////////////////////////////////////////


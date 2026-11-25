#ifndef FOURRES_GUI_H
#define FOURRES_GUI_H

#include <gtk/gtk.h>

typedef struct s_section {
  char *name;
  char *flags;
  guint64 size;
  guint64 address;
  guint64 offset;
} t_section;

typedef struct s_app {
  GtkWidget *window;
  GtkWidget *text;
  GtkWidget *hex_text;
  GtkWidget *strings_text;
  GtkWidget *symbols_text;
  GtkWidget *functions_text;
  GtkWidget *sections;
  GtkWidget *notebook;
  GtkWidget *status;
  GPtrArray *section_data;
  guint8 *binary;
  gsize binary_size;
  gboolean dark_theme;
  char *path;
  char *decompiler_output;
  int zoom;
} t_app;

void section_free(gpointer data);

#endif

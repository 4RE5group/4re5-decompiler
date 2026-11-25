#include "gui.h"

void section_free(gpointer data) {
  t_section *section = data;
  if (!section)
    return;
  g_free(section->name);
  g_free(section->flags);
  g_free(section);
}

#include "../types/binary_types.h"
#include "gui.h"
#include <fcntl.h>
#include <gtk/gtk.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>


static void set_status(t_app *app, const char *message)
{
	gtk_label_set_text(GTK_LABEL(app->status), message);
}

static const char *string_at_address(t_app *app, guint64 address)
{
	if (!app->section_data)
		return NULL;
	for (guint i = 0; i < app->section_data->len; i++)
	{
		t_section *section = g_ptr_array_index(app->section_data, i);
		if (address < section->address || address >= section->address + section->size)
			continue;

		guint64 offset = section->offset + address - section->address;
		if (offset >= app->binary_size)
			return NULL;

		const unsigned char *value = app->binary + offset;
		gsize length = 0;
		while (offset + length < app->binary_size && length < 160 && (g_ascii_isprint(value[length]) || value[length] == '\n' || value[length] == '\r' || value[length] == '\t'))
			length++;

		if (length >= 4)
			return (const char *)value;
	}
	return NULL;
}

static char *escape_string(const char *value)
{
	GString *escaped = g_string_new(NULL);
	for (gsize i = 0; value && value[i] && i < 160; i++)
	{
		unsigned char c = (unsigned char)value[i];
		if (c == '\n')					g_string_append(escaped, "\\n");
		else if (c == '\r')				g_string_append(escaped, "\\r");
		else if (c == '\t')				g_string_append(escaped, "\\t");
		else if (c == '\\')				g_string_append(escaped, "\\\\");
		else if (c == '"')				g_string_append(escaped, "\\\"");
		else if (g_ascii_isprint(c))	g_string_append_c(escaped, c);
		else							g_string_append_printf(escaped, "\\x%02x", c);
	}
	return g_string_free(escaped, FALSE);
}

static char *function_at_address(t_app *app, guint64 address)
{
	char **lines = g_strsplit(app->decompiler_output ? app->decompiler_output : "", "\n", -1);
	for (guint i = 0; lines[i]; i++)
	{
		if (!g_str_has_prefix(lines[i], "FUNCTION|"))
			continue;

		char **fields = g_strsplit(lines[i], "|", 5);
		guint64 symbol_address = fields[2] ? g_ascii_strtoull(fields[2], NULL, 16) : 0;
		char *result = (fields[1] && symbol_address == address) ? g_strdup(fields[1]) : NULL;

		g_strfreev(fields);
		if (result)
		{
			g_strfreev(lines);
			return result;
		}
	}
	g_strfreev(lines);
	return NULL;
}

static void set_text(t_app *app, const char *contents)
{
	GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(app->text));
	gtk_text_buffer_set_text(buffer, "", 0);
	GtkTextIter end;
	gtk_text_buffer_get_end_iter(buffer, &end);
	GString *plain = g_string_new(NULL);

	for (const char *p = contents ? contents : ""; *p; p++)
	{
		if ((guchar)*p == 0x1b && p[1] == '[')
		{
			p += 2;
			while (*p && !g_ascii_isalpha(*p))
				p++;
		}
		else
			g_string_append_c(plain, *p);
	}
	char **lines = g_strsplit(plain->str, "\n", -1);
	for (size_t i = 0; lines[i]; i++)
	{
		if (g_str_has_prefix(lines[i], "ELF|"))
		{
			// skip
		}
		else if (g_str_has_prefix(lines[i], "ELF_HEADER|"))
		{
			char **fields = g_strsplit(lines[i], "|", 3);
			if (fields[1] && fields[2])
			{
				char *header = g_strdup_printf("%-18s %s", fields[1], fields[2]);
				gtk_text_buffer_insert_with_tags_by_name(buffer, &end, header, -1, "header", NULL);
				g_free(header);
			}
			g_strfreev(fields);
		}
		else if (g_str_has_prefix(lines[i], "SECTION|"))
		{
			char **fields = g_strsplit(lines[i], "|", 6);
			if (fields[1] && fields[2] && fields[3] && fields[4] && fields[5])
			{
				if (!fields[1][0])
				{
					g_strfreev(fields);
					continue;
				}

				char *heading = g_strdup_printf("[%s]  VA 0x%s  offset 0x%s  size 0x%s  %s", fields[1], fields[2], fields[3], fields[4], fields[5]);
				gtk_text_buffer_insert_with_tags_by_name(buffer, &end, heading, -1, "mnemonic", NULL);
				g_free(heading);
			}
			g_strfreev(fields);
		}
		else if (g_str_has_prefix(lines[i], "SYMBOL|") || g_str_has_prefix(lines[i], "FUNCTION|"))
		{
			// skip
		}
		else if (g_str_has_prefix(lines[i], "ASM|"))
		{
			char **fields = g_strsplit(lines[i], "|", 5);
			if (fields[0] && fields[1] && fields[2] && fields[3] && fields[4])
			{
				const char *address_value = g_str_has_prefix(fields[1], "0x") ? fields[1] + 2 : fields[1];
				char *address = g_strdup_printf("0x%-16s", address_value);
				char *bytes = g_strdup_printf("%-32s", fields[2]);
				char *mnemonic = g_strdup_printf("%-10s", fields[3]);

				gtk_text_buffer_insert_with_tags_by_name(buffer, &end, address, -1, "address", NULL);
				guint64 instruction_address = g_ascii_strtoull(address_value, NULL, 16);
				char *function_name = function_at_address(app, instruction_address);
				if (function_name)
				{
					char *label = g_strdup_printf("  <%s>", function_name);
					gtk_text_buffer_insert_with_tags_by_name(buffer, &end, label, -1, "header", NULL);
					g_free(label);
					g_free(function_name);
				}

				gtk_text_buffer_insert(buffer, &end, "  ", -1);
				gtk_text_buffer_insert_with_tags_by_name(buffer, &end, bytes, -1, "bytes", NULL);
				gtk_text_buffer_insert(buffer, &end, "  ", -1);
				gtk_text_buffer_insert_with_tags_by_name(buffer, &end, mnemonic, -1, "mnemonic", NULL);
				gtk_text_buffer_insert(buffer, &end, "  ", -1);
				g_free(address);
				g_free(bytes);
				g_free(mnemonic);

				const char *operand = fields[4];
				while (*operand)
				{
					if (g_ascii_isxdigit(*operand) && (g_str_has_prefix(operand, "0x") || g_str_has_prefix(operand, "0X")))
					{
						const char *start = operand;
						char *end_number = NULL;
						guint64 value = g_ascii_strtoull(operand, &end_number, 0);
						if (end_number == start)
							end_number = (char *)start + 1;

						char *number = g_strndup(start, end_number - start);
						gtk_text_buffer_insert_with_tags_by_name(buffer, &end, number, -1, "constant", NULL);
						const char *resolved = string_at_address(app, value);
						if (resolved)
						{
							char *escaped = escape_string(resolved);
							char *annotation = g_strdup_printf("  ; \"%s\"", escaped);
							gtk_text_buffer_insert_with_tags_by_name(buffer, &end, annotation, -1, "string_ref", NULL);
							g_free(annotation);
							g_free(escaped);
						}

						g_free(number);
						operand = end_number;
					}
					else if (g_ascii_isalpha(*operand) || *operand == '%')
					{
						const char *start = operand++;
						while (g_ascii_isalnum(*operand))
							operand++;

						char *word = g_strndup(start, operand - start);
						const char *tag = NULL;
						const char *r64[] = {
							"rax", "rbx", "rcx", "rdx", "rsi", "rdi",
							"rbp", "rsp", "rip", "r8",  "r9",  "r10",
							"r11", "r12", "r13", "r14", "r15", NULL
						};
						const char *r32[] = {
							"eax",  "ebx",  "ecx",  "edx",  "esi",  "edi",
							"ebp",  "esp",  "r8d",  "r9d",  "r10d", "r11d",
							"r12d", "r13d", "r14d", "r15d", NULL
						};
						const char *r16[] = {
							"ax", "bx", "cx", "dx", "si",
							"di", "bp", "sp", NULL
						};
						const char *r8[] = {
							"al", "ah", "bl", "bh", "cl",
							"ch", "dl", "dh", NULL
						};

						for (int n = 0; r64[n]; n++)
							if (g_strcmp0(word, r64[n]) == 0)	tag = "reg64";
						for (int n = 0; r32[n]; n++)
							if (g_strcmp0(word, r32[n]) == 0)	tag = "reg32";
						for (int n = 0; r16[n]; n++)
							if (g_strcmp0(word, r16[n]) == 0)	tag = "reg16";
						for (int n = 0; r8[n]; n++)
							if (g_strcmp0(word, r8[n]) == 0)	tag = "reg8";
						if (tag)
							gtk_text_buffer_insert_with_tags_by_name(buffer, &end, word, -1, tag, NULL);
						else
							gtk_text_buffer_insert(buffer, &end, word, -1);
						g_free(word);
					} else {
						gtk_text_buffer_insert(buffer, &end, operand, 1);
						operand++;
					}
				}
			}
			g_strfreev(fields);
		} else if (lines[i][0])
			gtk_text_buffer_insert(buffer, &end, lines[i], -1);
		if (lines[i][0] && lines[i + 1] && lines[i + 1][0])
			gtk_text_buffer_insert(buffer, &end, "\n", 1);
	}
	g_strfreev(lines);
	g_string_free(plain, TRUE);
	gtk_text_buffer_set_modified(buffer, FALSE);
}

static void set_symbols(t_app *app, const char *contents)
{
	GString *table = g_string_new("NAME\t\tADDRESS\t\tSIZE\tBIND\tTYPE\tSECTION\n");
	GString *functions = g_string_new("FUNCTION\t\tADDRESS\t\tSIZE\tSECTION\n");
	char **lines = g_strsplit(contents ? contents : "", "\n", -1);
	for (guint i = 0; lines[i]; i++)
	{
		if (g_str_has_prefix(lines[i], "SYMBOL|"))
		{
			char **fields = g_strsplit(lines[i], "|", 7);
			if (fields[1] && fields[2] && fields[3] && fields[4] && fields[5] && fields[6])
				g_string_append_printf(table, "%-24s\t0x%-16s\t0x%-8s\t%s\t%s\t%s\n", fields[1], fields[2], fields[3], fields[4], fields[5], fields[6]);

			g_strfreev(fields);
		}
		else if (g_str_has_prefix(lines[i], "FUNCTION|"))
		{
			char **fields = g_strsplit(lines[i], "|", 5);
			if (fields[1] && fields[2] && fields[3] && fields[4])
				g_string_append_printf(functions, "%-24s\t0x%-16s\t0x%-8s\t%s\n", fields[1], fields[2], fields[3], fields[4]);
			g_strfreev(fields);
		}
	}
	gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(app->symbols_text)), table->str, -1);
	gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(app->functions_text)), functions->str, -1);
	g_string_free(table, TRUE);
	g_string_free(functions, TRUE);
	g_strfreev(lines);
}

// theme
static void	install_theme(t_app *app)
{
	GtkCssProvider *theme = gtk_css_provider_new();
	const char *css = app->dark_theme
		? "* { font-family: Lilex, 'DejaVu Sans Mono', monospace; }"
		"window, notebook, notebook > stack, scrolledwindow, viewport { "
		"background: #282828; color: #ebdbb2; }"
		"textview, textview text { background: #282828; color: #ebdbb2; "
		"caret-color: #fabd2f; }"
		"menubar, toolbar, statusbar { background: #3c3836; color: "
		"#ebdbb2; }"
		"menu, menuitem, notebook header { background: #3c3836; color: "
		"#ebdbb2; }"
		"menuitem:hover, button:hover, notebook tab:hover { background: "
		"#504945; }"
		"notebook tab:checked { background: #665c54; color: #fabd2f; }"
		"treeview, treeview.view { background: #32302f; color: #ebdbb2; }"
		"treeview.view:selected { background: #665c54; color: #fabd2f; }"
		"header, treeview header button { background: #504945; color: "
		"#ebdbb2; }"
		"scrollbar, trough { background: #3c3836; }"
		: "* { font-family: Lilex, 'DejaVu Sans Mono', monospace; }"
		"window, notebook, notebook > stack, scrolledwindow, viewport { "
		"background: #fbf1c7; color: #3c3836; }"
		"textview, textview text { background: #fbf1c7; color: #3c3836; "
		"caret-color: #b57614; }"
		"menubar, toolbar, statusbar { background: #ebdbb2; color: "
		"#3c3836; }"
		"menu, menuitem, notebook header { background: #f2e5bc; color: "
		"#3c3836; }"
		"menuitem:hover, button:hover, notebook tab:hover { background: "
		"#d5c4a1; }"
		"notebook tab:checked { background: #d5c4a1; color: #b57614; }"
		"treeview, treeview.view { background: #f9f0d0; color: #3c3836; }"
		"treeview.view:selected { background: #d5c4a1; color: #8f3f71; }"
		"header, treeview header button { background: #ebdbb2; color: "
		"#3c3836; }"
		"scrollbar, trough { background: #ebdbb2; }";

	gtk_css_provider_load_from_data(theme, css, -1, NULL);
	gtk_style_context_add_provider_for_screen(gdk_screen_get_default(), GTK_STYLE_PROVIDER(theme), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
	g_object_unref(theme);
	GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(app->text));
	const char *names[] = {
		"address",	"bytes", "mnemonic", "reg32",
		"reg16",	  "reg8",  "reg64",	"constant",
		"string_ref", "header"
	};
	const char *colors[] = {
		app->dark_theme ? "#a89984" : "#928374",
		app->dark_theme ? "#928374" : "#a89984",
		app->dark_theme ? "#83a598" : "#076678",
		"#fb4934",
		"#fabd2f",
		"#d3869b",
		"#83a598",
		"#b8bb26",
		"#8ec07c",
		"#b8bb26"
	};
	for (guint i = 0; i < G_N_ELEMENTS(names); i++)
	{
		GtkTextTag *tag = gtk_text_tag_table_lookup(gtk_text_buffer_get_tag_table(buffer), names[i]);
		if (!tag)
			tag = gtk_text_buffer_create_tag(buffer, names[i], NULL);
		g_object_set(tag, "foreground", colors[i], NULL);
	}
	GtkTextTag *mnemonic = gtk_text_tag_table_lookup(gtk_text_buffer_get_tag_table(buffer), "mnemonic");
	g_object_set(mnemonic, "weight", PANGO_WEIGHT_BOLD, NULL);
}

static void	toggle_theme(GtkWidget *widget, gpointer data)
{
	(void)widget;
	t_app *app = data;
	app->dark_theme = !app->dark_theme;
	install_theme(app);
}

static char	*run_decompiler(const char *path, int *status)
{
	int output_pipe[2];
	if (pipe(output_pipe) < 0)
	{
		*status = 1;
		return NULL;
	}
	pid_t child = fork();
	if (child < 0)
	{
		close(output_pipe[0]);
		close(output_pipe[1]);
		*status = 1;
		return NULL;
	}
	if (child == 0)
	{
		int fd = open(path, O_RDONLY);
		if (fd < 0)
			_exit(1);
		close(STDOUT_FILENO);
		dup2(output_pipe[1], STDOUT_FILENO);
		close(output_pipe[0]);
		close(output_pipe[1]);
		int result = detect_type(fd);
		fflush(stdout);
		close(fd);
		_exit(result);
	}
	close(output_pipe[1]);

	GString *output = g_string_new(NULL);
	char buffer[4096];
	ssize_t bytes;
	while ((bytes = read(output_pipe[0], buffer, sizeof(buffer))) > 0)
		g_string_append_len(output, buffer, bytes);

	close(output_pipe[0]);
	int child_status = 1;
	waitpid(child, &child_status, 0);

	*status = WIFEXITED(child_status) ? WEXITSTATUS(child_status) : 1;

	return g_string_free(output, FALSE);
}

static __attribute__((unused)) char *format_disassembly(const char *output)
{
	GString *formatted = g_string_new(NULL);
	char **lines = g_strsplit(output ? output : "", "\n", -1);
	for (guint i = 0; lines[i]; i++)
	{
		const char *p = lines[i];
		while (g_ascii_isspace(*p))
			p++;

		char *colon = strchr((char *)p, ':');
		if (colon && g_ascii_isxdigit(*p))
		{
			char *end = NULL;
			guint64 address = g_ascii_strtoull(p, &end, 16);
			if (end == colon)
			{
				p = colon + 1;
				while (g_ascii_isspace(*p))
					p++;

				GString *bytes = g_string_new(NULL);
				while (g_ascii_isxdigit(p[0]) && p[1] && g_ascii_isxdigit(p[1]) && (p[2] == 0 || g_ascii_isspace(p[2])))
				{
					if (bytes->len)
						g_string_append_c(bytes, ' ');

					g_string_append_len(bytes, p, 2);
					p += 2;
					while (g_ascii_isspace(*p))
						p++;
				}
				if (bytes->len && *p)
				{
					const char *mnemonic = p;
					while (*p && !g_ascii_isspace(*p))
						p++;

					char *op = g_strstrip(g_strdup(p));
					char *mn = g_strndup(mnemonic, p - mnemonic);
					g_string_append_printf(formatted, "ASM|%llx|%s|%s|%s\n", (unsigned long long)address, bytes->str, mn, op);
					g_free(mn);
					g_free(op);
				}
				else if (lines[i][0])
					g_string_append_printf(formatted, "%s\n", lines[i]);

				g_string_free(bytes, TRUE);
				continue;
			}
		}
		if (lines[i][0])
			g_string_append_printf(formatted, "%s\n", lines[i]);
	}
	g_strfreev(lines);
	return g_string_free(formatted, FALSE);
}

static void show_section(t_app *app, t_section *section)
{
	if (!section)
		return;

	GString *hex = g_string_new(NULL);
	guint64 limit = MIN(section->size, app->binary_size - MIN(section->offset, app->binary_size));
	for (guint64 i = 0; i < limit; i += 16)
	{
		guint64 address = section->address + i;
		g_string_append_printf(hex, "%016llx  ", (unsigned long long)address);
		for (guint64 j = 0; j < 16; j++)
		{
			if (i + j < limit)
				g_string_append_printf(hex, "%02x ", app->binary[section->offset + i + j]);
			else
				g_string_append(hex, "   ");
			if (j == 7)
				g_string_append_c(hex, ' ');
		}
		g_string_append(hex, " | ");
		for (guint64 j = 0; j < 16 && i + j < limit; j++)
		{
			guchar c = app->binary[section->offset + i + j];
			g_string_append_c(hex, g_ascii_isprint(c) ? c : '.');
		}
		g_string_append_c(hex, '\n');
	}
	GtkTextBuffer *hex_buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(app->hex_text));
	gtk_text_buffer_set_text(hex_buffer, hex->str, -1);
	g_string_free(hex, TRUE);
	if (app->decompiler_output)
	{
		set_text(app, app->decompiler_output);
		char *status = g_strdup_printf("%s  ·  VA 0x%llx  ·  file offset 0x%llx  ·  %llu bytes", section->name, (unsigned long long)section->address, (unsigned long long)section->offset, (unsigned long long)section->size);
		set_status(app, status);
		g_free(status);
	}
}

static void section_selected(GtkTreeSelection *selection, gpointer data)
{
	t_app *app = data;
	GtkTreeModel *model;
	GtkTreeIter iter;
	if (gtk_tree_selection_get_selected(selection, &model, &iter))
	{
		guint index;
		gtk_tree_model_get(model, &iter, 5, &index, -1);
		if (index < app->section_data->len)
			show_section(app, g_ptr_array_index(app->section_data, index));
	}
}

static void populate_strings(t_app *app)
{
	GString *strings = g_string_new("FILE OFFSET	   STRING\n----------------  "
									"--------------------------------\n");
	gsize i = 0;
	while (i < app->binary_size)
	{
		if (!g_ascii_isprint(app->binary[i]))
		{
			i++;
			continue;
		}
		gsize start = i;
		while (i < app->binary_size && g_ascii_isprint(app->binary[i]))
			i++;

		if (i - start >= 4)
		{
			char *value = g_strndup((char *)app->binary + start, i - start);
			g_string_append_printf(strings, "0x%08llx		%s\n", (unsigned long long)start, value);
			g_free(value);
		}
	}
	GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(app->strings_text));
	gtk_text_buffer_set_text(buffer, strings->str, -1);
	g_string_free(strings, TRUE);
}

static gboolean load_binary(t_app *app, const char *path)
{
	GError *error = NULL;
	g_free(app->binary);
	app->binary = NULL;
	app->binary_size = 0;
	if (!g_file_get_contents(path, (char **)&app->binary, &app->binary_size, &error))
	{
		set_status(app, error->message);
		g_error_free(error);
		return FALSE;
	}

	int exit_status = 0;
	char *headers = run_decompiler(path, &exit_status);
	if (!headers || exit_status != 0)
	{
		set_status(app, "Unsupported file or the project decompiler could not read it");
		g_free(headers);
		return FALSE;
	}

	g_free(app->decompiler_output);
	app->decompiler_output = g_strdup(headers);
	g_ptr_array_set_size(app->section_data, 0);
	GtkListStore *store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(app->sections)));
	gtk_list_store_clear(store);
	char **lines = g_strsplit(headers, "\n", -1);
	t_section *last_section = NULL;
	for (guint i = 0; lines[i]; i++)
	{
		char name[256];
		unsigned long long size, address, offset;
		char flags[32];
		if (sscanf(lines[i], "SECTION|%255[^|]|%llx|%llx|%llx|%31s", name, &address, &offset, &size, flags) == 5)
		{
			t_section *section = g_new0(t_section, 1);
			section->name = g_strdup(name);
			section->flags = g_strdup(flags);
			section->size = size;
			section->address = address;
			section->offset = offset;
			g_ptr_array_add(app->section_data, section);
			last_section = section;
			GtkTreeIter iter;
			gtk_list_store_append(store, &iter);
			char *address_text = g_strdup_printf("0x%llx", address);
			char *size_text = g_strdup_printf("0x%llx", size);
			char *offset_text = g_strdup_printf("0x%llx", offset);
			gtk_list_store_set(store, &iter, 0, name, 1, address_text, 2, size_text, 3, offset_text, 4, section->flags, 5, app->section_data->len - 1, -1);
			g_free(address_text);
			g_free(size_text);
			g_free(offset_text);
		}
	}
	g_strfreev(lines);
	set_symbols(app, headers);
	g_free(headers);
	GtkTreeIter flag_iter;
	if (gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &flag_iter))
	{
		for (guint i = 0; i < app->section_data->len; i++)
		{
			t_section *section = g_ptr_array_index(app->section_data, i);
			gtk_list_store_set(store, &flag_iter, 4, section->flags, -1);
			gtk_tree_model_iter_next(GTK_TREE_MODEL(store), &flag_iter);
		}
	}
	if (!app->section_data->len)
	{
		set_status(app, "No ELF sections found");
		return FALSE;
	}
	populate_strings(app);
	g_free(app->path);
	app->path = g_strdup(path);
	char *title = g_strdup_printf("%s — 4re5 Decompiler", path);
	gtk_window_set_title(GTK_WINDOW(app->window), title);
	g_free(title);
	GtkTreeIter first, iter;
	if (gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &first))
	{
		iter = first;
		gboolean selected = FALSE;
		do {
			char *name = NULL;
			gtk_tree_model_get(GTK_TREE_MODEL(store), &iter, 0, &name, -1);
			if (g_strcmp0(name, ".text") == 0)
			{
				gtk_tree_selection_select_iter(gtk_tree_view_get_selection(GTK_TREE_VIEW(app->sections)), &iter);
				selected = TRUE;
			}
			g_free(name);
		}
		while (!selected && gtk_tree_model_iter_next(GTK_TREE_MODEL(store), &iter));

		if (!selected)
			gtk_tree_selection_select_iter(gtk_tree_view_get_selection(GTK_TREE_VIEW(app->sections)), &first);
	}
	return TRUE;
}

static gboolean decompile(t_app *app, const char *path)
{
	return load_binary(app, path);
}

static void open_file(GtkWidget *widget, gpointer data)
{
	(void)widget;
	t_app *app = data;
	GtkWidget *dialog = gtk_file_chooser_dialog_new("Open binary", GTK_WINDOW(app->window), GTK_FILE_CHOOSER_ACTION_OPEN, "Cancel", GTK_RESPONSE_CANCEL, "Open", GTK_RESPONSE_ACCEPT, NULL);
	if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT)
	{
		char *path = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
		decompile(app, path);
		g_free(path);
	}
	gtk_widget_destroy(dialog);
}

static void reopen_file(GtkWidget *widget, gpointer data)
{
	(void)widget;
	t_app *app = data;
	if (app->path)
		decompile(app, app->path);
	else
		open_file(NULL, app);
}

static void save_output(GtkWidget *widget, gpointer data)
{
	(void)widget;
	t_app *app = data;
	GtkWidget *dialog = gtk_file_chooser_dialog_new(
							"Save decompilation", GTK_WINDOW(app->window),
							GTK_FILE_CHOOSER_ACTION_SAVE, "Cancel", GTK_RESPONSE_CANCEL, "Save",
							GTK_RESPONSE_ACCEPT, NULL);
	gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(dialog),
			TRUE);
	gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(dialog),
									  "decompilation.txt");
	if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT)
	{
		char *path = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
		GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(app->text));
		GtkTextIter start, end;
		gtk_text_buffer_get_bounds(buffer, &start, &end);
		char *contents = gtk_text_buffer_get_text(buffer, &start, &end, FALSE);
		GError *error = NULL;
		if (!g_file_set_contents(path, contents, -1, &error))
		{
			GtkWidget *alert = gtk_message_dialog_new(
								   GTK_WINDOW(app->window), GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR,
								   GTK_BUTTONS_CLOSE, "Could not save output: %s", error->message);
			gtk_dialog_run(GTK_DIALOG(alert));
			gtk_widget_destroy(alert);
			g_error_free(error);
		}
		g_free(contents);
		g_free(path);
	}
	gtk_widget_destroy(dialog);
}

static void quit_app(GtkWidget *widget, gpointer data)
{
	(void)widget;
	gtk_widget_destroy(GTK_WIDGET(((t_app *)data)->window));
}

static void copy_text(GtkWidget *widget, gpointer data)
{
	(void)widget;
	t_app *app = data;
	GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(app->text));
	GtkClipboard *clipboard = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
	gtk_text_buffer_copy_clipboard(buffer, clipboard);
}

static void select_all(GtkWidget *widget, gpointer data)
{
	(void)widget;
	t_app *app = data;
	GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(app->text));
	GtkTextIter start, end;
	gtk_text_buffer_get_bounds(buffer, &start, &end);
	gtk_text_buffer_select_range(buffer, &start, &end);
}

static void find_text(GtkWidget *widget, gpointer data)
{
	(void)widget;
	t_app *app = data;
	GtkWidget *dialog = gtk_dialog_new_with_buttons(
							"Find in output", GTK_WINDOW(app->window), GTK_DIALOG_MODAL, "Cancel",
							GTK_RESPONSE_CANCEL, "Find", GTK_RESPONSE_ACCEPT, NULL);
	GtkWidget *entry = gtk_entry_new();
	gtk_entry_set_placeholder_text(GTK_ENTRY(entry), "Instruction or text");
	gtk_container_set_border_width(
		GTK_CONTAINER(gtk_dialog_get_content_area(GTK_DIALOG(dialog))), 12);
	gtk_container_add(
		GTK_CONTAINER(gtk_dialog_get_content_area(GTK_DIALOG(dialog))), entry);
	gtk_widget_show_all(dialog);
	if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT)
	{
		const char *query = gtk_entry_get_text(GTK_ENTRY(entry));
		GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(app->text));
		GtkTextIter start, match_start, match_end;
		gboolean found;
		gtk_text_buffer_get_iter_at_mark(buffer, &start, gtk_text_buffer_get_insert(buffer));
		found = gtk_text_iter_forward_search(&start, query, GTK_TEXT_SEARCH_CASE_INSENSITIVE, &match_start, &match_end, NULL);
		if (!found)
		{
			gtk_text_buffer_get_start_iter(buffer, &start);
			found = gtk_text_iter_forward_search(&start, query,
												 GTK_TEXT_SEARCH_CASE_INSENSITIVE,
												 &match_start, &match_end, NULL);
		}
		if (found)
		{
			gtk_text_buffer_select_range(buffer, &match_start, &match_end);
			gtk_text_view_scroll_to_iter(GTK_TEXT_VIEW(app->text), &match_start, 0.1,
										 FALSE, 0, 0);
		}
		else
			set_status(app, "No matching text found");
	}
	gtk_widget_destroy(dialog);
}

static char *prompt_value(t_app *app, const char *title, const char *hint)
{
	GtkWidget *dialog = gtk_dialog_new_with_buttons(
							title, GTK_WINDOW(app->window), GTK_DIALOG_MODAL, "Cancel",
							GTK_RESPONSE_CANCEL, "Go", GTK_RESPONSE_ACCEPT, NULL);
	GtkWidget *entry = gtk_entry_new();
	gtk_entry_set_placeholder_text(GTK_ENTRY(entry), hint);
	gtk_container_set_border_width(
		GTK_CONTAINER(gtk_dialog_get_content_area(GTK_DIALOG(dialog))), 12);
	gtk_container_add(
		GTK_CONTAINER(gtk_dialog_get_content_area(GTK_DIALOG(dialog))), entry);
	gtk_widget_show_all(dialog);
	char *value = NULL;
	if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT)
		value = g_strdup(gtk_entry_get_text(GTK_ENTRY(entry)));
	gtk_widget_destroy(dialog);
	return value;
}

// search options
static void go_to_address(GtkWidget *widget, gpointer data)
{
	(void)widget;
	t_app *app = data;
	char *input = prompt_value(app, "Go to ELF virtual address", "0x8048000");
	if (!input)
		return;
	char *end = NULL;
	guint64 address = g_ascii_strtoull(input, &end, 0);
	if (end == input || *end)
	{
		set_status(app, "Enter a valid hexadecimal or decimal address");
		g_free(input);
		return;
	}
	for (guint i = 0; i < app->section_data->len; i++)
	{
		t_section *section = g_ptr_array_index(app->section_data, i);
		if (address >= section->address && address - section->address < section->size)
		{
			GtkTreeModel *model = gtk_tree_view_get_model(GTK_TREE_VIEW(app->sections));
			GtkTreeIter iter;
			if (gtk_tree_model_iter_nth_child(model, &iter, NULL, i))
				gtk_tree_selection_select_iter(
					gtk_tree_view_get_selection(GTK_TREE_VIEW(app->sections)), &iter);
			GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(app->text));
			GtkTextIter start, match_start, match_end;
			char *needle = g_strdup_printf("0x%llx", (unsigned long long)address);
			gtk_text_buffer_get_start_iter(buffer, &start);
			if (gtk_text_iter_forward_search(&start, needle, GTK_TEXT_SEARCH_CASE_INSENSITIVE, &match_start, &match_end, NULL))
			{
				gtk_text_buffer_select_range(buffer, &match_start, &match_end);
				gtk_text_view_scroll_to_iter(GTK_TEXT_VIEW(app->text), &match_start,
											 0.1, FALSE, 0, 0);
				gtk_notebook_set_current_page(GTK_NOTEBOOK(app->notebook), 0);
			}
			else
				set_status(app, "Address is inside the section but has no decoded instruction");
			g_free(needle);
			g_free(input);
			return;
		}
	}
	set_status(app, "Address does not belong to a file-backed ELF section");
	g_free(input);
}

static gboolean parse_pattern(const char *input, gint pattern[256], guint *length)
{
	char **tokens = g_strsplit_set(input, " ,:\t", -1);
	*length = 0;
	for (guint i = 0; tokens[i]; i++)
	{
		if (!*tokens[i])
			continue;
		if (*length == 256)
		{
			g_strfreev(tokens);
			return FALSE;
		}
		if (g_str_equal(tokens[i], "??") || g_str_equal(tokens[i], "?"))
			pattern[(*length)++] = -1;
		else
		{
			char *end = NULL;
			long value = strtol(tokens[i], &end, 16);
			if (end == tokens[i] || *end || value < 0 || value > 255)
			{
				g_strfreev(tokens);
				return FALSE;
			}
			pattern[(*length)++] = (gint)value;
		}
	}
	g_strfreev(tokens);
	return *length != 0;
}

static guint64 address_for_offset(t_app *app, guint64 offset)
{
	for (guint i = 0; i < app->section_data->len; i++)
	{
		t_section *section = g_ptr_array_index(app->section_data, i);
		if (offset >= section->offset && offset - section->offset < section->size)
			return section->address + offset - section->offset;
	}
	return G_MAXUINT64;
}

static void search_bytes(GtkWidget *widget, gpointer data)
{
	(void)widget;
	t_app *app = data;
	char *input = prompt_value(app, "Search byte pattern", "48 8b ?? ?? 89");
	if (!input)
		return;
	gint pattern[256];
	guint length;
	if (!parse_pattern(input, pattern, &length))
	{
		set_status(
			app, "Use hexadecimal bytes separated by spaces; ?? matches any byte");
		g_free(input);
		return;
	}
	GString *matches = g_string_new("FILE OFFSET	   ELF VIRTUAL ADDRESS\n");
	guint count = 0;
	for (gsize i = 0; i + length <= app->binary_size; i++)
	{
		guint j;
		for (j = 0; j < length; j++)
			if (pattern[j] >= 0 && app->binary[i + j] != pattern[j])
				break;
		if (j == length)
		{
			guint64 va = address_for_offset(app, i);
			if (va == G_MAXUINT64)
				g_string_append_printf(matches,
									   "0x%08llx		(no section mapping)\n",
									   (unsigned long long)i);
			else
				g_string_append_printf(matches, "0x%08llx		0x%llx\n",
									   (unsigned long long)i, (unsigned long long)va);
			count++;
			if (count == 1000)
			{
				g_string_append(matches, "Results capped at 1000 matches.\n");
				break;
			}
		}
	}
	if (!count)
		g_string_append(matches, "No matches found.\n");
	GtkWidget *dialog = gtk_message_dialog_new(
							GTK_WINDOW(app->window), GTK_DIALOG_MODAL, GTK_MESSAGE_INFO,
							GTK_BUTTONS_CLOSE, "%u byte pattern match%s", count,
							count == 1 ? "" : "es");
	GtkWidget *view = gtk_text_view_new();
	gtk_text_view_set_monospace(GTK_TEXT_VIEW(view), TRUE);
	gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(view)),
							 matches->str, -1);
	GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
	gtk_widget_set_size_request(scroll, 500, 300);
	gtk_container_add(GTK_CONTAINER(scroll), view);
	gtk_container_add(
		GTK_CONTAINER(gtk_dialog_get_content_area(GTK_DIALOG(dialog))), scroll);
	gtk_widget_show_all(dialog);
	gtk_dialog_run(GTK_DIALOG(dialog));
	gtk_widget_destroy(dialog);
	g_string_free(matches, TRUE);
	g_free(input);
}

static void find_string(GtkWidget *widget, gpointer data)
{
	t_app *app = data;
	gtk_notebook_set_current_page(GTK_NOTEBOOK(app->notebook), 2);
	find_text(widget, data);
}

static void change_zoom(t_app *app, int delta)
{
	app->zoom += delta;
	if (app->zoom < 7)
		app->zoom = 7;
	if (app->zoom > 30)
		app->zoom = 30;
	GtkCssProvider *provider = gtk_css_provider_new();
	char *css = g_strdup_printf("textview { font-family: Lilex, 'DejaVu Sans "
								"Mono', monospace; font-size: %dpt; }",
								app->zoom);
	gtk_css_provider_load_from_data(provider, css, -1, NULL);
	gtk_style_context_add_provider(gtk_widget_get_style_context(app->text),
								   GTK_STYLE_PROVIDER(provider),
								   GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
	g_object_unref(provider);
	g_free(css);
}

// menu widget
static void zoom_in(GtkWidget *widget, gpointer data)
{
	(void)widget;
	change_zoom(data, 1);
}
static void zoom_out(GtkWidget *widget, gpointer data)
{
	(void)widget;
	change_zoom(data, -1);
}
static void zoom_reset(GtkWidget *widget, gpointer data)
{
	(void)widget;
	((t_app *)data)->zoom = 11;
	change_zoom(data, 0);
}

static void show_extensions(GtkWidget *widget, gpointer data)
{
	(void)widget;
	GtkWidget *dialog = gtk_message_dialog_new(
							GTK_WINDOW(((t_app *)data)->window), GTK_DIALOG_MODAL, GTK_MESSAGE_INFO,
							GTK_BUTTONS_CLOSE,
							"Extensions are not available yet. ELF 32-bit and 64-bit x86 files are "
							"supported by the project's native ELF and x86 decoder.");
	gtk_dialog_run(GTK_DIALOG(dialog));
	gtk_widget_destroy(dialog);
}

static GtkWidget *add_item(GtkWidget *menu, const char *label,
						   GCallback callback, t_app *app)
{
	GtkWidget *item = gtk_menu_item_new_with_label(label);
	gtk_menu_shell_append(GTK_MENU_SHELL(menu), item);
	if (callback)
		g_signal_connect(item, "activate", callback, app);
	return item;
}

static GtkWidget *make_menu(const char *label, GtkWidget *bar)
{
	GtkWidget *root = gtk_menu_item_new_with_mnemonic(label);
	GtkWidget *menu = gtk_menu_new();
	gtk_menu_item_set_submenu(GTK_MENU_ITEM(root), menu);
	gtk_menu_shell_append(GTK_MENU_SHELL(bar), root);
	return menu;
}

static void about(GtkWidget *widget, gpointer data)
{
	(void)widget;
	gtk_show_about_dialog(
		GTK_WINDOW(((t_app *)data)->window), "program-name", "4re5 Decompiler",
		"version", "0.1", "comments",
		"Browse ELF sections, bytes, strings, and x86 disassembly.", NULL);
}


static GtkWidget *create_text_view(gboolean cursor_visible)
{
	GtkWidget *view = gtk_text_view_new();
	gtk_text_view_set_editable(GTK_TEXT_VIEW(view), FALSE);
	gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(view), cursor_visible);
	gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(view), GTK_WRAP_NONE);
	gtk_widget_set_margin_start(view, 12);
	gtk_widget_set_margin_end(view, 12);
	gtk_widget_set_margin_top(view, 10);
	return view;
}

static GtkWidget *create_section_tree(t_app *app)
{
	GType types[] = {G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
					 G_TYPE_STRING, G_TYPE_STRING, G_TYPE_UINT
					};
	GtkListStore *store = gtk_list_store_newv(G_N_ELEMENTS(types), types);
	GtkWidget *tree = gtk_tree_view_new_with_model(GTK_TREE_MODEL(store));
	g_object_unref(store);
	const char *titles[] = {"Section", "Virtual address", "Size", "File offset",
							"Flags"
						   };
	for (guint i = 0; i < G_N_ELEMENTS(titles); i++)
{
		GtkCellRenderer *renderer = gtk_cell_renderer_text_new();
		GtkTreeViewColumn *column = gtk_tree_view_column_new_with_attributes(
										titles[i], renderer, "text", i, NULL);
		gtk_tree_view_column_set_resizable(column, TRUE);
		gtk_tree_view_append_column(GTK_TREE_VIEW(tree), column);
	}
	g_signal_connect(gtk_tree_view_get_selection(GTK_TREE_VIEW(tree)), "changed",
					 G_CALLBACK(section_selected), app);
	return tree;
}

static void append_data_tab(GtkWidget *notebook, const char *title, GtkWidget **view, gboolean cursor_visible)
{
	GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
								   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	*view = create_text_view(cursor_visible);
	gtk_container_add(GTK_CONTAINER(scroll), *view);
	gtk_notebook_append_page(GTK_NOTEBOOK(notebook), scroll,
							 gtk_label_new(title));
}

int main(int argc, char **argv)
{
	gtk_init(&argc, &argv);
	t_app app = {0};
	app.zoom = 11;
	app.dark_theme = TRUE;
	app.window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_title(GTK_WINDOW(app.window), "4re5 Decompiler");
	gtk_window_set_default_size(GTK_WINDOW(app.window), 1050, 700);
	g_signal_connect(app.window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
	GtkWidget *layout = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
	gtk_container_add(GTK_CONTAINER(app.window), layout);
	GtkWidget *bar = gtk_menu_bar_new();
	gtk_box_pack_start(GTK_BOX(layout), bar, FALSE, FALSE, 0);
	GtkWidget *file = make_menu("_File", bar);
	add_item(file, "Open binary…", G_CALLBACK(open_file), &app);
	add_item(file, "Reopen current", G_CALLBACK(reopen_file), &app);
	add_item(file, "Save output as…", G_CALLBACK(save_output), &app);
	add_item(file, "Quit", G_CALLBACK(quit_app), &app);
	GtkWidget *edit = make_menu("_Edit", bar);
	add_item(edit, "Find…", G_CALLBACK(find_text), &app);
	add_item(edit, "Find string…", G_CALLBACK(find_string), &app);
	add_item(edit, "Search byte pattern…", G_CALLBACK(search_bytes), &app);
	add_item(edit, "Go to ELF address…", G_CALLBACK(go_to_address), &app);
	add_item(edit, "Copy", G_CALLBACK(copy_text), &app);
	add_item(edit, "Select all", G_CALLBACK(select_all), &app);
	GtkWidget *view = make_menu("_View", bar);
	add_item(view, "Switch light/dark theme", G_CALLBACK(toggle_theme), &app);
	add_item(view, "Zoom in", G_CALLBACK(zoom_in), &app);
	add_item(view, "Zoom out", G_CALLBACK(zoom_out), &app);
	add_item(view, "Reset zoom", G_CALLBACK(zoom_reset), &app);
	GtkWidget *extensions = make_menu("_Extensions", bar);
	add_item(extensions, "Manage extensions…", G_CALLBACK(show_extensions), &app);
	GtkWidget *about_menu = make_menu("_About", bar);
	add_item(about_menu, "About 4re5 Decompiler", G_CALLBACK(about), &app);
	GtkWidget *toolbar = gtk_toolbar_new();
	gtk_toolbar_set_style(GTK_TOOLBAR(toolbar), GTK_TOOLBAR_BOTH_HORIZ);
	GtkToolItem *open_button = gtk_tool_button_new(NULL, "Open binary");
	gtk_tool_button_set_icon_name(GTK_TOOL_BUTTON(open_button),
								  "folder-open-symbolic");
	g_signal_connect(open_button, "clicked", G_CALLBACK(open_file), &app);
	gtk_toolbar_insert(GTK_TOOLBAR(toolbar), open_button, -1);
	GtkToolItem *save_button = gtk_tool_button_new(NULL, "Save output");
	gtk_tool_button_set_icon_name(GTK_TOOL_BUTTON(save_button),
								  "document-save-as-symbolic");
	g_signal_connect(save_button, "clicked", G_CALLBACK(save_output), &app);
	gtk_toolbar_insert(GTK_TOOLBAR(toolbar), save_button, -1);
	gtk_box_pack_start(GTK_BOX(layout), toolbar, FALSE, FALSE, 0);

	/* Main workspace: section navigator on the left, data tabs on the right. */
	GtkWidget *paned = gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);
	gtk_box_pack_start(GTK_BOX(layout), paned, TRUE, TRUE, 0);
	app.sections = create_section_tree(&app);
	GtkWidget *section_scroll = gtk_scrolled_window_new(NULL, NULL);
	gtk_container_add(GTK_CONTAINER(section_scroll), app.sections);
	gtk_widget_set_size_request(section_scroll, 320, -1);
	gtk_paned_pack1(GTK_PANED(paned), section_scroll, FALSE, FALSE);
	app.notebook = gtk_notebook_new();
	gtk_paned_pack2(GTK_PANED(paned), app.notebook, TRUE, FALSE);
	append_data_tab(app.notebook, "Assembly", &app.text, TRUE);
	append_data_tab(app.notebook, "Raw bytes", &app.hex_text, FALSE);
	append_data_tab(app.notebook, "Strings", &app.strings_text, FALSE);
	append_data_tab(app.notebook, "Symbols", &app.symbols_text, FALSE);
	append_data_tab(app.notebook, "Functions", &app.functions_text, FALSE);
	install_theme(&app);
	GtkWidget *statusbar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
	gtk_widget_set_margin_start(statusbar, 10);
	gtk_widget_set_margin_top(statusbar, 5);
	gtk_widget_set_margin_bottom(statusbar, 5);
	app.status = gtk_label_new("Open an ELF binary to inspect its sections, "
							   "disassembly, bytes, and strings");
	gtk_widget_set_halign(app.status, GTK_ALIGN_START);
	gtk_box_pack_start(GTK_BOX(statusbar), app.status, TRUE, TRUE, 0);
	gtk_box_pack_end(GTK_BOX(layout), statusbar, FALSE, FALSE, 0);
	app.section_data = g_ptr_array_new_with_free_func(section_free);
	set_text(&app, "Open a binary to inspect its section disassembly.");
	if (argc > 1)
		decompile(&app, argv[1]);
	gtk_widget_show_all(app.window);
	gtk_main();
	g_free(app.path);
	g_free(app.decompiler_output);
	g_free(app.binary);
	g_ptr_array_free(app.section_data, TRUE);
	return 0;
}

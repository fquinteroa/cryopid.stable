#define WNCK_I_KNOW_THIS_IS_UNSTABLE

#include <X11/Xlib.h>
#include <X11/cursorfont.h>
#include <X11/Xmu/WinUtil.h>
#include <gtk/gtk.h>
#include <gdk/gdkx.h>
#include <libwnck/libwnck.h>
#include <unistd.h>

/* Some widgets to keep track of */
GtkWidget *pid_entry;
GtkWidget *title_label;
GtkWidget *output_file;
GtkWidget *go_button;

static Window GetWindow(Display *dpy)
{
	Window target_win = None, root = RootWindow(dpy, DefaultScreen(dpy)); // FIXME
	XEvent event;
	Cursor cursor;
	int buttons = 0, dummy;
	unsigned int udummy;

	cursor = XCreateFontCursor(dpy, XC_crosshair);
	if (XGrabPointer(dpy, root, False, ButtonPressMask|ButtonReleaseMask,
			GrabModeSync, GrabModeAsync, root, cursor, CurrentTime) != GrabSuccess)
		return -1;

	while (!target_win || buttons) {
		XAllowEvents(dpy, SyncPointer, CurrentTime);
		XWindowEvent(dpy, root, ButtonPressMask|ButtonReleaseMask, &event);
		if (event.type == ButtonPress) {
			if (target_win == None)
				target_win = event.xbutton.subwindow;
			buttons++;
		} else if (event.type == ButtonRelease && buttons)
			buttons--;
	}

	XUngrabPointer(dpy, CurrentTime);
	XFreeCursor(dpy, cursor);

	if (XGetGeometry(dpy, target_win, &root, &dummy, &dummy,
				&udummy, &udummy, &udummy, &udummy) && target_win != root)
		target_win = XmuClientWindow(dpy, target_win);

	return target_win;
}

static void window_selector(GtkWidget *widget, GdkEvent *event, gpointer *data)
{
	Window xw;
	char text[20];
	pid_t pid;

	xw = GetWindow(GDK_DISPLAY());

	WnckWindow *ww = wnck_window_get(xw);
	if (ww == NULL)
		return;

	pid = wnck_window_get_pid(ww);
	if (pid == 0) {
		gtk_label_set_text(GTK_LABEL(title_label),
				"No PID associated with that window");
		gtk_entry_set_text(GTK_ENTRY(pid_entry), "");
		return;
	}

	snprintf(text, sizeof(text), "%d", pid);
	gtk_entry_set_text(GTK_ENTRY(pid_entry), text);
	gtk_label_set_text(GTK_LABEL(title_label), wnck_window_get_name(ww));
	gtk_widget_set_sensitive(go_button, TRUE);
}

static void freeze_it(GtkWidget *widget, GdkEvent *event, gpointer *data)
{
	printf("pid: %s\n", gtk_entry_get_text(GTK_ENTRY(pid_entry)));
	if (!fork()) {
		execl("../src/freeze", "freeze", "-l", 
				gtk_entry_get_text(GTK_ENTRY(output_file)),
				gtk_entry_get_text(GTK_ENTRY(pid_entry)),
				NULL);
	}
}

static void create_main_window()
{
	GtkWidget *window, *button, *table, *fchooser, *label;

	window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_title(GTK_WINDOW(window), "GCryoPID");
	
	g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
	g_signal_connect(window, "delete-event", G_CALLBACK(gtk_false), NULL);

	table = gtk_table_new(5, 2, FALSE);

	button = gtk_button_new_with_label("Click to select a Window");
	g_signal_connect(button, "clicked", G_CALLBACK(window_selector), NULL);
	gtk_table_attach(GTK_TABLE(table), button,
			0, 2, 0, 1, GTK_EXPAND | GTK_FILL, 0, 2, 2);

	label = gtk_label_new("Process ID: ");
	pid_entry = gtk_entry_new();
	gtk_table_attach(GTK_TABLE(table), label,
			0, 1, 1, 2, 0, 0, 2, 2);
	gtk_table_attach(GTK_TABLE(table), pid_entry,
			1, 2, 1, 2, GTK_EXPAND | GTK_FILL, 0, 2, 2);

	label = gtk_label_new("Window title: ");
	title_label = gtk_label_new("");
	gtk_label_set_justify(GTK_LABEL(title_label), GTK_JUSTIFY_LEFT);
	gtk_table_attach(GTK_TABLE(table), label,
			0, 1, 2, 3, 0, 0, 2, 2);
	gtk_table_attach(GTK_TABLE(table), title_label,
			1, 2, 2, 3, GTK_EXPAND | GTK_FILL, 0, 2, 2);

	label = gtk_label_new("Save as: ");
	output_file = gtk_entry_new();
	gtk_table_attach(GTK_TABLE(table), label,
			0, 1, 3, 4, 0, 0, 2, 2);
	gtk_table_attach(GTK_TABLE(table), output_file,
			1, 2, 3, 4, GTK_EXPAND | GTK_FILL, 0, 2, 2);

	label = gtk_label_new("Save in folder: ");
	fchooser = gtk_file_chooser_button_new("Select directory",
			GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER);
	gtk_table_attach(GTK_TABLE(table), label,
			0, 1, 4, 5, 0, 0, 2, 2);
	gtk_table_attach(GTK_TABLE(table), fchooser,
			1, 2, 4, 5, GTK_EXPAND | GTK_FILL, 0, 2, 2);

	go_button = gtk_button_new_with_label("Freeze it!");
	g_signal_connect(go_button, "clicked", G_CALLBACK(freeze_it), NULL);
	gtk_table_attach(GTK_TABLE(table), go_button,
			0, 2, 5, 6, GTK_EXPAND | GTK_FILL, 0, 2, 2);
	gtk_widget_set_sensitive(go_button, FALSE);

	gtk_container_add(GTK_CONTAINER(window), table);

	gtk_window_set_default_size(GTK_WINDOW(window), 500, -1);
	gtk_widget_show_all(window);
}

static void do_wnck()
{
	WnckScreen *wnck_screen;
	wnck_screen = wnck_screen_get_default();
	wnck_screen_force_update(wnck_screen);
}

int main(int argc, char *argv[])
{
	//g_set_application_name("GCryoPID");

	gtk_init(&argc, &argv);

	create_main_window();
	do_wnck();

	gtk_main();
	
	return 0;
}


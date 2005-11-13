#define WNCK_I_KNOW_THIS_IS_UNSTABLE

#include <X11/Xlib.h>
#include <X11/cursorfont.h>
#include <X11/Xmu/WinUtil.h>
#include <gtk/gtk.h>
#include <gdk/gdkx.h>
#include <libwnck/libwnck.h>

static Window GetWindow(Display *dpy)
{
	Cursor cursor;
	XEvent event;
	Window target_win = None, root = RootWindow(dpy, DefaultScreen(dpy)); // FIXME
	int status, buttons = 0, dummy;
	unsigned int udummy;

	cursor = XCreateFontCursor(dpy, XC_crosshair);

	status = XGrabPointer(dpy, root, False, ButtonPressMask|ButtonReleaseMask,
			GrabModeSync, GrabModeAsync, root, cursor, CurrentTime);
	if (status != GrabSuccess)
		return -1;

	while ((target_win == None) || (buttons != 0)) {
		XAllowEvents(dpy, SyncPointer, CurrentTime);
		XWindowEvent(dpy, root, ButtonPressMask|ButtonReleaseMask, &event);
		switch (event.type) {
			case ButtonPress:
					if (target_win == None) {
						target_win = event.xbutton.subwindow;
						if (target_win == None)
							target_win = root;
					}
					buttons++;
					break;
			case ButtonRelease:
					if (buttons > 0)
						buttons--;
					break;
		}
	}

	XUngrabPointer(dpy, CurrentTime);

	if (XGetGeometry(dpy, target_win, &root, &dummy, &dummy,
				&udummy, &udummy, &udummy, &udummy) && target_win != root)
		target_win = XmuClientWindow(dpy, target_win);

	return target_win;
}

static void point_and_freeze(GtkWidget *widget, GdkEvent *event, gpointer *data)
{
	Window xw;
	xw = GetWindow(GDK_DISPLAY());
	g_print("X Window: 0x%lx\n", xw);

	WnckWindow *ww = wnck_window_get(xw);
	if (ww == NULL) {
		Window *children, root, parent;
		Status res;
		unsigned int nchildren;
		printf("No WnckWindow. Trying child.\n");
		res = XQueryTree(GDK_DISPLAY(), xw, &root, &parent, &children, &nchildren);
		if (res != Success) {
			printf("XQueryTree failed: %d.\n", res);
			return;
		}
		if (nchildren != 1) {
			printf("Got %d children. Don't know what to do!\n", nchildren);
			return;
		}
		if ((ww = wnck_window_get(*children)) == NULL) {
			printf("Still no joy. Aborting\n");
			XFree(children);
			return;
		}
		XFree(children);
	}

	printf("window pid %d\n", wnck_window_get_pid(ww));
}

static void create_main_window()
{
	GtkWidget *window;
	GtkWidget *gobutton;
	WnckScreen *wnck_screen;

	window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_widget_set_name(window, "GCryoPID Main Window");
	
	g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
	g_signal_connect(window, "delete-event", G_CALLBACK(gtk_false), NULL);

	gobutton = gtk_button_new_with_label("Point and freeze!");
	g_signal_connect(gobutton, "clicked", G_CALLBACK(point_and_freeze), NULL);
	gtk_container_add(GTK_CONTAINER(window), gobutton);

	gtk_widget_show_all(window);

	wnck_screen = wnck_screen_get_default();
	wnck_screen_force_update(wnck_screen);
}

int main(int argc, char *argv[])
{
	//g_set_application_name("GCryoPID");

	gtk_init(&argc, &argv);

	create_main_window();

	gtk_main();
	
	return 0;
}


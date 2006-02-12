#define WNCK_I_KNOW_THIS_IS_UNSTABLE

#include <X11/Xlib.h>
#include <X11/cursorfont.h>
#include <X11/Xmu/WinUtil.h>
#include <gtk/gtk.h>
#include <gdk/gdkx.h>
#include <libwnck/libwnck.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <unistd.h>

static int disp_height, disp_width;
static volatile int moving;
static char* target;

static void move_it(pid_t pid)
{
	static char pid_str[10];
	snprintf(pid_str, sizeof(pid_str), "%d", pid);
	if (!fork()) {
		printf("Executing cryopid -l -n %s %s %s\n", target, "dummy", pid_str);
		execl("../src/freeze", "freeze", "-lkn", target,
				"dummy", pid_str, NULL);
		exit(1);
	}
}

static void sigchld_handler(int sig)
{
	while (waitpid(-1, NULL, WNOHANG) != -1);
	moving = 0;
}

static void cb_geometry_changed(WnckWindow *window, gpointer data)
{
	GdkScreen *screen;
	gint x, y;
	pid_t pid;
	GdkModifierType mask;

	if (moving)
		return;

	gdk_display_get_pointer(gdk_display_get_default(), &screen, &x, &y, &mask);

	pid = wnck_window_get_pid(window);

	if (pid && (mask || GDK_BUTTON1_MASK) &&
			(x == 0 || x == disp_width-1 || y == 0 || y == disp_height-1)) {
		moving = 1;
		move_it(pid);
	}
}

static void connect_window(WnckWindow *window)
{
	g_signal_connect_object(G_OBJECT(window),
		  "geometry_changed", G_CALLBACK (cb_geometry_changed), NULL, 0);
}

static void cb_window_opened (WnckScreen *screen, WnckWindow *window, gpointer data)
{
	connect_window(window);
}

static void setup_callbacks (WnckScreen *screen)
{
	GList *tmp;
  
	tmp = wnck_screen_get_windows (screen);
	while (tmp != NULL) {
		connect_window(WNCK_WINDOW (tmp->data));
		tmp = tmp->next;
	}
  
	g_signal_connect (G_OBJECT (screen), "window_opened",
			G_CALLBACK (cb_window_opened), NULL);
}

static void start_wnck()
{
	GdkScreen *screen;
	WnckScreen *wnck_screen;

	signal(SIGCHLD, sigchld_handler);

	wnck_screen = wnck_screen_get_default();
	wnck_screen_force_update(wnck_screen);
	setup_callbacks(wnck_screen);

	screen = gdk_display_get_default_screen(gdk_display_get_default());
	disp_height = gdk_screen_get_height(screen);
	disp_width  = gdk_screen_get_width(screen);
}

int main(int argc, char *argv[])
{
	gtk_init(&argc, &argv);

	if (argc != 2) {
		printf("Usage: %s <target host>\n", argv[0]);
		return 1;
	}
	target = argv[1];

	start_wnck();

	gtk_main();
	
	return 0;
}


#include <gtk/gtk.h>
#include <signal.h>
#include <string.h>
#include <elf.h>
#include <link.h>
#include <sys/types.h>

#include "cryopid.h"

static void* resolve(void *l, char *what)
{
	struct link_map *lm = (struct link_map *)(l);
	
	Elf32_Dyn *dyn;
	Elf32_Sym *sym;
	char *strtab;

	void *val = NULL;
	
	for(;lm != NULL; lm = lm->l_next) {
		dyn = (Elf32_Dyn *)(unsigned int)(lm->l_ld);
		//printf("dyn: 0x%lx (0x%lx)\n", dyn, lm->l_addr);
		sym = NULL;
		strtab = NULL;

		for(; dyn->d_tag != DT_NULL; dyn++) {
			if(dyn->d_tag == DT_STRTAB) strtab = (char *)(dyn->d_un.d_ptr);
			if(dyn->d_tag == DT_SYMTAB) sym = (Elf32_Sym *)(dyn->d_un.d_ptr);
		}
		
		while(sym) {
			if(sym->st_name > 0x100000)
				break;
			if(strcmp(strtab + sym->st_name, what)  == 0) {
				val = (void*)(lm->l_addr + sym->st_value);
				if (sym->st_value) {
					debug("--> we have found %s @ 0x%08x (0x%08lx)\n", strtab + sym->st_name, sym->st_value, (unsigned long)(lm->l_addr + sym->st_value));
					return val;
				}
			}
			
			sym++;
		}
		
	}
	return val;
}

static void* find_lm()
{
	Elf32_Ehdr *elf;
	Elf32_Phdr *phdr;
	Elf32_Dyn *dyn;
	int i, cnt;
	unsigned long *got;
	struct link_map *lm;
	/* FIXME: find dynamically... preferably from reading image */
	//elf = (Elf32_Ehdr *)((unsigned int)(main) & 0xfffff000);
	elf = (Elf32_Ehdr*)0x8048000;
	phdr = (Elf32_Phdr *)((unsigned char *)(elf) + elf->e_phoff);
	
	for(i = 0; i < elf->e_phnum; i++) {
		if(phdr[i].p_type == PT_DYNAMIC) break;
	}

	if(i == elf->e_phnum) {
		printf("Not a dynamic elf file?\n");
		return NULL;
	}

	phdr += i;

	dyn = (Elf32_Dyn *)(phdr->p_vaddr);
	cnt = phdr->p_filesz / sizeof(Elf32_Dyn);

	got = NULL;
	for(i = 0; i < cnt; i++) {
		if(dyn[i].d_tag == DT_PLTGOT) got = (unsigned long *)(dyn[i].d_un.d_ptr);
	}

	if(got == NULL) {
		printf("Unable to find GOT\n");
		return NULL;
	}

	lm = (struct link_map *)(got[1]);
	
	printf("link_map @ 0x%08lx\n", (unsigned long)lm);

	return lm;
}

void cryopid_migrate_gtk_windows()
{
	void *lm = find_lm();
	GdkDisplay *(*_gdk_display_get_default)() = resolve(lm, "gdk_display_get_default");
	GdkDisplayManager *(*_gdk_display_manager_get)() = resolve(lm, "gdk_display_manager_get");
	void (*_gdk_display_manager_set_default_display)(GdkDisplayManager*, GdkDisplay*) = resolve(lm, "gdk_display_manager_set_default_display");
	GdkDisplay *(*_gdk_display_open)(char*) = resolve(lm, "gdk_display_open");
	GdkScreen *(*_gdk_display_get_default_screen)(GdkDisplay*) = resolve(lm, "gdk_display_get_default_screen");
	GList *(*_gdk_window_get_toplevels)() = resolve(lm, "gdk_window_get_toplevels");
	void (*_gdk_window_get_user_data)(GdkWindow*,void**) = resolve(lm, "gdk_window_get_user_data");
	void (*_gtk_window_set_screen)(GtkWindow*,GdkScreen*) = resolve(lm, "gtk_window_set_screen");
	GType (*gtk_window_get_type)(void) = resolve(lm, "gtk_window_get_type");
	void (*_g_list_foreach)(GList*,GFunc,void*) = resolve(lm, "g_list_foreach");
	void (*_g_list_free)(GList*) = resolve(lm, "g_list_free");
	void (*_gdk_display_close)(GdkDisplay*) = resolve(lm, "gdk_display_close");
	int (*g_type_check_instance_is_a)(GTypeInstance*, GType) = resolve(lm, "g_type_check_instance_is_a");

	GList *top_levels = _gdk_window_get_toplevels();
	GdkDisplay *old_display = _gdk_display_get_default();
	printf("Opening\n");
	GdkDisplay *new_display = _gdk_display_open(":0");
	GdkDisplayManager *m = _gdk_display_manager_get();
	_gdk_display_manager_set_default_display(m, new_display);

	GdkScreen *screen = _gdk_display_get_default_screen(new_display);
	static void move_it(GdkWindow *w, GdkScreen *s) {
		GtkWindow *wd;
		_gdk_window_get_user_data(w, (void*)&wd);
		if (GTK_IS_WINDOW(wd))
			_gtk_window_set_screen (wd, s);
	}
	printf("Moving\n");
	_g_list_foreach(top_levels, (GFunc)move_it, (void*)screen);
	_g_list_free(top_levels);
	//printf("Closing\n");
	//_gdk_display_close(old_display);
}

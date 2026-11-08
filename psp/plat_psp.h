#ifndef PSPKIT_TUNNEL_PLAT_PSP_H
#define PSPKIT_TUNNEL_PLAT_PSP_H

/* The console's half of plat.h, and the little tunnel.c tells it. */

void plat_psp_set_dir(const char *dir);
void plat_psp_set_log(void (*line)(const char *text));
int plat_random_ok(void);
int plat_exists(const char *name);
int plat_remove(const char *name);
void plat_psp_set_wait(void (*wait)(unsigned ms));

#endif

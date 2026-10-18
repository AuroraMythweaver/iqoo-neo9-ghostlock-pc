/*
 * cmd_deploy.c -- `deploy` subcommand (payload staging only).
 */
#include "internal.h"

int cmd_deploy(void)
{
    gl_pack p;
    if (gl_pack_open(g_opt.pack, &p) != 0) return 2;
    gl_env_serial();
    gl_adb a = gl_env_adb();
    int rc = gl_do_deploy(&a, &p);
    gl_pack_close(&p);
    return rc == 0 ? 0 : 2;
}

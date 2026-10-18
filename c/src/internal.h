/*
 * internal.h -- cross-command helpers (not part of the public header).
 */
#ifndef GL_INTERNAL_H
#define GL_INTERNAL_H

#include "gl.h"

/* adb context built from g_opt (serial is resolved lazily) */
gl_adb gl_env_adb(void);
char *gl_env_serial(void);

/* payload helpers (deploy.c) */
char *gl_expected_release(const gl_pack *p, const gl_opt *o);
int gl_need_deploy(const gl_adb *a, const gl_pack *p);
int gl_do_deploy(const gl_adb *a, const gl_pack *p);
int gl_select_ko(const gl_opt *o, char **ko_path);
int gl_install_ko_wrapper(const gl_adb *a, const gl_opt *o, const char *ko_path);

/* profile helpers */
int gl_load_profile_file(const char *path, gl_profile *prof, char **err);

/* misc */
const char *gl_opt_profile_name(const gl_opt *o);
char *gl_device_tmp_file(const char *tag, const void *data, size_t n);

#endif

#ifndef HOS_SD_LOGIN_SHIM_H
#define HOS_SD_LOGIN_SHIM_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

int sd_pid_get_session(pid_t pid, char **session);
int sd_pid_get_user_unit(pid_t pid, char **unit);
int sd_pid_get_cgroup(pid_t pid, char **cgroup);
int sd_uid_get_display(uid_t uid, char **session);
int sd_uid_get_sessions(uid_t uid, int require_active, char ***sessions);
int sd_session_get_class(const char *session, char **clazz);
int sd_session_get_seat(const char *session, char **seat);
int sd_session_get_state(const char *session, char **state);
int sd_session_get_type(const char *session, char **type);
int sd_session_is_active(const char *session);

#ifdef __cplusplus
}
#endif

#endif

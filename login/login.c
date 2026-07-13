/*
 * Minimal Apple-compatible preauthenticated login session launcher.
 *
 * This intentionally implements only the option surface used by terminal
 * applications such as iTerm2.  Password authentication, PAM, Kerberos, and
 * login accounting belong in a complete login implementation and are not
 * silently emulated here.
 */

#include <stdint.h>
#include <errno.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

struct local_account {
	char *name;
	char *home;
	char *shell;
	uid_t uid;
	gid_t gid;
};

static void
usage(void)
{
	fprintf(stderr, "usage: login -fp[-ql] user [program [argument ...]]\n");
}

static const char *
last_path_component(const char *path)
{
	const char *slash = strrchr(path, '/');
	return slash == NULL ? path : slash + 1;
}

static int
lookup_local_account(const char *requested_name, struct local_account *account)
{
	FILE *passwd_file;
	char line[4096];

	passwd_file = fopen("/etc/passwd", "r");
	if (passwd_file == NULL)
		return -1;

	while (fgets(line, sizeof(line), passwd_file) != NULL) {
		char *fields[7];
		char *cursor = line;
		char *end;
		unsigned long uid;
		unsigned long gid;

		for (size_t index = 0; index < 7; ++index)
			fields[index] = strsep(&cursor, ":");
		if (fields[6] == NULL || strcmp(fields[0], requested_name) != 0)
			continue;
		fields[6][strcspn(fields[6], "\r\n")] = '\0';

		errno = 0;
		uid = strtoul(fields[2], &end, 10);
		if (errno != 0 || *fields[2] == '\0' || *end != '\0' ||
		    (unsigned long)(uid_t)uid != uid)
			break;
		errno = 0;
		gid = strtoul(fields[3], &end, 10);
		if (errno != 0 || *fields[3] == '\0' || *end != '\0' ||
		    (unsigned long)(gid_t)gid != gid)
			break;

		account->name = strdup(fields[0]);
		account->home = strdup(fields[5][0] == '\0' ? "/" : fields[5]);
		account->shell = strdup(fields[6][0] == '\0' ? "/bin/sh" : fields[6]);
		account->uid = (uid_t)uid;
		account->gid = (gid_t)gid;
		fclose(passwd_file);
		if (account->name == NULL || account->home == NULL ||
		    account->shell == NULL) {
			errno = ENOMEM;
			return -1;
		}
		return 0;
	}

	fclose(passwd_file);
	errno = ENOENT;
	return -1;
}

int
main(int argc, char **argv)
{
	int option;
	int preauthenticated = 0;
	int preserve_environment = 0;
	int preserve_directory = 0;
	struct local_account account = { 0 };
	const char *home;
	const char *shell;
	char *login_argv0;

	while ((option = getopt(argc, argv, "fpql")) != -1) {
		switch (option) {
		case 'f':
			preauthenticated = 1;
			break;
		case 'p':
			preserve_environment = 1;
			break;
		case 'q':
			break;
		case 'l':
			preserve_directory = 1;
			break;
		default:
			usage();
			return 2;
		}
	}

	if (!preauthenticated || !preserve_environment || optind >= argc) {
		fprintf(stderr,
		    "login: only preauthenticated environment-preserving sessions "
		    "(-fp) are supported\n");
		usage();
		return 2;
	}
	if (lookup_local_account(argv[optind++], &account) == -1) {
		fprintf(stderr, "login: unknown user\n");
		return 1;
	}
	if (geteuid() != 0 && (account.uid != geteuid() || account.uid != getuid() ||
	    account.gid != getegid())) {
		fprintf(stderr,
		    "login: -f may only select the current user without root privileges\n");
		return 1;
	}
	home = account.home;
	shell = account.shell;

	if (setenv("HOME", home, 1) == -1 ||
	    setenv("SHELL", shell, 1) == -1 ||
	    setenv("USER", account.name, 1) == -1 ||
	    setenv("LOGNAME", account.name, 1) == -1) {
		perror("login: setenv");
		return 1;
	}

	if (geteuid() == 0 && (setgroups(1, &account.gid) == -1 ||
	    setgid(account.gid) == -1 || setuid(account.uid) == -1)) {
		perror("login: credentials");
		return 1;
	}
	if (!preserve_directory && chdir(home) == -1) {
		fprintf(stderr, "login: cannot change directory to %s: %s\n",
		    home, strerror(errno));
		return 1;
	}

	if (optind < argc) {
		execvp(argv[optind], &argv[optind]);
		fprintf(stderr, "login: cannot execute %s: %s\n",
		    argv[optind], strerror(errno));
		return errno == ENOENT ? 127 : 126;
	}

	if (asprintf(&login_argv0, "-%s", last_path_component(shell)) == -1) {
		fprintf(stderr, "login: out of memory\n");
		return 1;
	}
	char *const shell_argv[] = { login_argv0, NULL };
	execv(shell, shell_argv);
	fprintf(stderr, "login: cannot execute %s: %s\n", shell, strerror(errno));
	return errno == ENOENT ? 127 : 126;
}

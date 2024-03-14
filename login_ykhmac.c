/*
 * Copyright (c) 2024 LEVAI Daniel
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	* Redistributions of source code must retain the above copyright
 *	notice, this list of conditions and the following disclaimer.
 *	* Redistributions in binary form must reproduce the above copyright
 *	notice, this list of conditions and the following disclaimer in the
 *	documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL LEVAI Daniel BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*
 * MODE_CHALLENGE and MODE_RESPONSE sections are copied from
 * src/libexec/login_yubikey/login_yubikey.c
 */
/*
 * Copyright (c) 2010 Daniel Hartmeier <daniel@benzedrine.cx>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    - Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    - Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <sys/time.h>
#include <sys/resource.h>

#include <login_cap.h>

#include <readpassphrase.h>


#include "common.h"
#include "login_ykhmac.h"
#include "ykhmac.h"


int
main(int argc, char *argv[])
{
	char		fail = 0;

	struct		rlimit rl;
	login_cap_t	*lc = NULL;

	int		rpp_flags = 0;

	struct passwd	*pw = NULL;

	FILE		*back = NULL;
	int		mode = 0, c, count = -1;
	char		*class = NULL, *username = NULL;

	char		password_static[1024];
	char		*password = NULL;
	char		*password_hash = NULL;

	char		response[1024];	/* auth type response, not related to YubiKey */

	char		*cfg_state_dir = NULL;
	int		cfg_standalone = 0;

	char		state_file_dir[PATH_MAX + 1];


	rl.rlim_cur = 0;
	rl.rlim_max = 0;
	(void)setrlimit(RLIMIT_CORE, &rl);

	(void)setpriority(PRIO_PROCESS, 0, 0);

	openlog("login_ykhmac", LOG_PID, LOG_AUTH);

	while ((c = getopt(argc, argv, "v:s:d")) != -1) {
		switch (c) {
		case 'v':
			break;
		case 's':	/* service */
			if (strncmp(optarg, "login", 5) == 0) {
				mode = MODE_LOGIN;
			} else if (strncmp(optarg, "challenge", 9) == 0) {
				mode = MODE_CHALLENGE;
			} else if (strncmp(optarg, "response", 8) == 0) {
				mode = MODE_RESPONSE;
			} else {
				syslog(LOG_ERR, "%s: invalid service", optarg);
				fail++;
			}
			break;
		case 'd':
			back = stdout;
			break;
		default:
			syslog(LOG_ERR, "Unknown parameter");
			fail++;
		}
	}

	switch (argc - optind) {
		case 2:
			class = argv[optind + 1];
			/*FALLTHROUGH*/
		case 1:
			username = argv[optind];
			break;
		default:
			syslog(LOG_ERR, "Too many parameters");
			goto fail;
	}

	/* bail if there was an error previously */
	if (fail) {
		goto fail;
	}

	if (back == NULL && (back = fdopen(3, "r+")) == NULL) {
		syslog(LOG_ERR, "reopening back channel: %m");
		goto fail;
	}

	switch (mode) {
		case MODE_LOGIN:
			rpp_flags = RPP_ECHO_OFF;
			rpp_flags |= RPP_REQUIRE_TTY;

			if ((password = readpassphrase("Password:", password_static, sizeof(password_static), rpp_flags)) == NULL) {
				syslog(LOG_ERR, "Unable to read passphrase: %m");
				goto fail;
			}

			break;
		case MODE_CHALLENGE:
			fprintf(back, BI_SILENT "\n");
			exit(AUTH_OK);
			break;
		case MODE_RESPONSE:
			mode = 0;
			while (++count < sizeof(response)  &&  read(3, &response[count], 1) == 1) {
				if (response[count] == '\0' && ++mode == 2)
					break;
				if (response[count] == '\0' && mode == 1)
					password = response + count + 1;
			}

			if (mode < 2) {
				syslog(LOG_ERR, "user %s: protocol error on back channel", username);
				goto fail;
			}


			break;
		default:
			syslog(LOG_ERR, "Unsupported authentication mode");
			goto fail;
			break;
	}

	/* if defined in login.conf(5), get the global state file directory path */
	lc = login_getclass(class);
	if (!lc) {
		syslog(LOG_ERR, "unknown class: %s", class);
		goto fail;
	}
	cfg_state_dir = login_getcapstr(lc, CAP_STATE_DIR, NULL, NULL);
	cfg_standalone = login_getcapbool(lc, CAP_STANDALONE, 0);
	login_close(lc);

	if (cfg_state_dir) {
		if (strlen(cfg_state_dir) <= PATH_MAX) {
			if (snprintf(state_file_dir, sizeof(state_file_dir), "%s/%s", cfg_state_dir, username) < 0) {
				syslog(LOG_ERR, "Error while setting up global state directory: %m");
				goto fail;
			}
		} else {
			syslog(LOG_ERR, "Invalid global state directory: '%s'", state_file_dir);
			goto fail;
		}
	} else {
		pw = getpwnam(username);
		if (!pw) {
			syslog(LOG_ERR, "Could not find '%s' in password database: %m", username);
			goto fail;
		}

		if (snprintf(state_file_dir, sizeof(state_file_dir), "%s/%s", pw->pw_dir, STATE_DIR_USER_HOME) < 0) {
			syslog(LOG_ERR, "Error while setting up per-user state directory: %m");
			goto fail;
		}
	}

	syslog(LOG_DEBUG, "%s(): username='%s', state_file_dir='%s', standalone=%d", __func__, username, state_file_dir, cfg_standalone);

	if (!cfg_standalone) {
		/* reuse (and check) user's password (hash) */
		if ((pw = getpwnam_shadow(username)))
			password_hash = strdup(pw->pw_passwd);

		if (!password_hash) {
			syslog(LOG_ERR, "Could not find '%s' in password database: %m", username);
			goto fail;
		}

		if (crypt_checkpass(password, password_hash) == 0) {
			explicit_bzero(password, strlen(password));
			password = password_hash;
		} else {
			syslog(LOG_ERR, "Invalid password");
			goto fail;
		}
	}

	if (ykhmac_check(username, password, state_file_dir)) {
		fprintf(back, BI_AUTH "\n");
		syslog(LOG_NOTICE, "Authentication OK for '%s'", username);

		closelog();
		exit(AUTH_OK);
	}

fail:
	syslog(LOG_NOTICE, "Authentication FAIL for '%s'", username == NULL ? "<unknown>" : username);
	closelog();

	if (back)
		fprintf(back, BI_REJECT "\n");
	exit(AUTH_FAILED);
} /* main() */

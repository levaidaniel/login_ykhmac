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
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS AND CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/* Bits and pieces -- heck, whole functions taken from the
 * yubikey-personalization repository, namely ykchalresp.c */
/*
 * Copyright (c) 2011-2013 Yubico AB.
 * All rights reserved.
 *
 * Author : Fredrik Thulin <fredrik@yubico.com>
 *
 * Some basic code copied from ykpersonalize.c.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <fcntl.h>
#include <dirent.h>

#include <sha2.h>

#include "common.h"
#include "ykhmac.h"


static int	yk_check_firmware(YK_KEY *);
static void	yk_report_error(void);


char
ykhmac_check(const char *username, const char *password,
		const char *state_file_dir)
{
	YK_KEY		*yk_key = 0;
	int		yk_cmd = 0;
	unsigned int	yk_serial = 0;
	int		yk_slot = 0;
	const char	*errstr = NULL;

	bool		may_block = true;

	char		state_file_path[PATH_MAX + 1];
	char		*state_file_name = NULL;
	unsigned int	state_file_name_serial = 0;
	int		sf = -1;

	char		*state_file_data = NULL;
	char		*state_file_line = NULL;

	DIR		*sd = NULL;
	struct dirent	*dir = NULL;

	char		challenge[SHA256_DIGEST_STRING_LENGTH];	/* includes +1 for NUL-termination */

	SHA2_CTX	sha_ctx;
	unsigned char	response[SHA1_MAX_BLOCK_SIZE];
	char		response_hex[SHA1_MAX_BLOCK_SIZE * 2 + 1];
	char		response_hash[SHA512_DIGEST_STRING_LENGTH];	/* includes +1 for NUL-termination */
	char		*response_hash_db = NULL, *salt_db = NULL;

	int		pos = 0;
	ssize_t		ret = -1;

	char 		success	= 0;


	yk_errno = 0;

	if (!yk_init()) {
		goto exit;
	}

	if (!state_file_dir) {
		syslog(LOG_ERR, "No state file directory was specified");
		goto exit;
	}

	SHA256Data((const unsigned char *)password, strlen(password), challenge);

	/* shouldn't happen(tm): */
	if (sizeof(challenge) - 1 > YKHMAC_CHALLENGE_MAXLEN) {	/* don't need to account for the terminating NUL in challenge's size here */
		syslog(LOG_ERR, "Challenge is longer than the maximum allowed size");
		yk_errno = YK_EWRONGSIZ;
		goto exit;
	}


	/* list files in the state directory and get the configured serial numbers */
	sd = opendir(state_file_dir);
	if (!sd) {
		syslog(LOG_ERR, "Could not open state directory: %m");
		goto exit;
	}

	while ((dir = readdir(sd)) != NULL) {
		if (strncmp(dir->d_name, ".", 1) == 0)
			continue;

		state_file_name_serial = strtonum(dir->d_name, 0, 99999999, &errstr);
		if (errstr != NULL) {
			syslog(LOG_ERR, "Could not convert state file name ('%s') to serial number: %s", dir->d_name, errstr);
			continue;
		}
		state_file_name = dir->d_name;

		/* iterate over the available YubiKeys, and search for the serial numbers */
		for (char yk_dev = 0; yk_dev < YKHMAC_DEV_MAX; yk_dev++) {
			if (!(yk_key = yk_open_key(yk_dev))) {
				continue;
			}

			if (!yk_check_firmware(yk_key)) {
				goto exit;
			}

			if (!yk_get_serial(yk_key, 1, 0, &yk_serial)) {
				syslog(LOG_ERR, "Could not read serial number from YubiKey device #%d!", yk_dev);
				goto exit;
			}


			if (yk_serial != state_file_name_serial) {
				if (yk_key && !yk_close_key(yk_key)) {
					goto exit;
				} else {
					continue;
				}
			}


			if (snprintf(state_file_path, sizeof(state_file_path), "%s/%s", state_file_dir, state_file_name) < 0) {
				syslog(LOG_ERR, "Error while setting up state file path: %m");
				goto exit;
			}


			/* open and read state file */
			sf = open(state_file_path, O_RDONLY);
			if (sf < 0) {
				syslog(LOG_ERR, "Could not open state file: %m");
				goto exit;
			}

			state_file_data = malloc(STATE_FILE_DATA_SIZE + 1);
			if (!state_file_data) {
				syslog(LOG_ERR, "Unable to allocate memory (state_file_data): %m");
				goto exit;
			}
			do {
				ret = read(sf, state_file_data + pos, STATE_FILE_DATA_SIZE - pos);
				pos += ret;
			} while (ret > 0  &&  pos < STATE_FILE_DATA_SIZE);
			close(sf);

			if (pos < STATE_FILE_DATA_SIZE) {
				syslog(LOG_ERR, "State file size is suspiciously small: %d", pos);
				goto exit;
			}

			state_file_data[(pos > 0 ? pos : 0)] = '\0';


			/* extract lines from the state file */
			while ((state_file_line = strsep(&state_file_data, "\n")) != NULL) {
				/* 1st line is slot no. */
				if (yk_slot == 0) {
					yk_slot = strtonum(state_file_line, 1, 2, &errstr);
					if (errstr != NULL) {
						syslog(LOG_ERR, "Could not convert slot number: %s", errstr);
						goto exit;
					}
				/* 2nd line is salt */
				} else if (salt_db == NULL) {
					salt_db = strndup(state_file_line, SALT_LENGTH);
				/* 3rd line is expected response */
				} else if (response_hash_db == NULL) {
					response_hash_db = strndup(state_file_line, sizeof(response_hash));
				}
			}
			free(state_file_data); state_file_data = NULL;


			syslog(LOG_INFO, "Using YubiKey slot #%d on device #%d", yk_slot, yk_dev);

			switch(yk_slot) {
				case 1:
					yk_cmd = SLOT_CHAL_HMAC1;
					break;
				case 2:
					yk_cmd = SLOT_CHAL_HMAC2;
					break;
				default:
					syslog(LOG_ERR, "YubiKey slot #%d is invalid!", yk_slot);
					yk_errno = YK_EINVALIDCMD;
					goto exit;
			}


			explicit_bzero(response, sizeof(response));
			if (!yk_challenge_response(yk_key, yk_cmd, may_block,
				sizeof(challenge) - 1, (const unsigned char *)challenge,	/* don't need to account for the terminating NUL in challenge's size here */
				sizeof(response), response))
			{
				goto exit;
			}
			explicit_bzero(challenge, sizeof(challenge));


			yubikey_hex_encode((char *)response_hex, (const char *)response, YKHMAC_RESPONSE_MAXLEN);
			explicit_bzero(response, sizeof(response));

			explicit_bzero(response_hash, sizeof(response_hash));
			SHA512Init(&sha_ctx);
			SHA512Update(&sha_ctx, (const unsigned char *)response_hex, strnlen(response_hex, YKHMAC_RESPONSE_MAXLEN * 2));
			SHA512Update(&sha_ctx, (const unsigned char *)salt_db, SALT_LENGTH);
			SHA512End(&sha_ctx, response_hash);
			explicit_bzero(salt_db, SALT_LENGTH);
			explicit_bzero(response_hex, sizeof(response_hex));

			if (memcmp(response_hash, response_hash_db, sizeof(response_hash)) == 0)
				success++;

			explicit_bzero(response_hash_db, sizeof(response_hash_db));
			free(response_hash_db); response_hash_db = NULL;

			explicit_bzero(response_hash, sizeof(response_hash));

			goto exit;
		}
	}


exit:
	if (sd)
		closedir(sd);

	explicit_bzero(challenge, sizeof(challenge));
	explicit_bzero(response, sizeof(response));
	explicit_bzero(response_hex, sizeof(response_hex));
	explicit_bzero(response_hash, sizeof(response_hash));
	explicit_bzero(salt_db, sizeof(salt_db));
	free(response_hash_db); response_hash_db = NULL;
	if (response_hash_db)
		explicit_bzero(response_hash_db, sizeof(response_hash));

	if (success) {
		return(1);
	} else {
		yk_report_error();
		if (yk_key && !yk_close_key(yk_key)) {
			yk_report_error();
		}

		return(0);
	}
} /* ykhmac_check() */


static int
yk_check_firmware(YK_KEY *yk_key)
{
	YK_STATUS *st = ykds_alloc();

	if (!yk_get_status(yk_key, st)) {
		syslog(LOG_ERR, "Could not get YubiKey status");
		ykds_free(st);
		return 0;
	}

	if (ykds_version_major(st) < 2 ||
	    (ykds_version_major(st) == 2
	     && ykds_version_minor(st) < 2)) {
		syslog(LOG_ERR, "Challenge-response not supported before YubiKey 2.2");
		ykds_free(st);
		return 0;
	}

	ykds_free(st);
	return 1;
} /* yk_check_firmware() */


static void
yk_report_error(void)
{
	if (yk_errno) {
		if (yk_errno == YK_EUSBERR) {
			syslog(LOG_ERR, "USB error: %s\n",
				yk_usb_strerror());
		} else {
			syslog(LOG_ERR, "YubiKey core error: %s\n",
				yk_strerror(yk_errno));
		}
	}
} /* yk_report_error() */

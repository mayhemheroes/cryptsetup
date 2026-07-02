// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * cryptsetup/mayhem/crypt_load_oracle.c
 *
 * Self-contained golden oracle over the SAME crypt_load() header-parser path the fuzz harnesses
 * exercise. No device-mapper, no loop device, no root: crypt_format() and crypt_load() operate on
 * a plain 16 MiB regular file, exactly as the fuzz harnesses do (they write the input into a
 * 16 MiB temp file and call crypt_load).
 *
 * For each LUKS type:
 *   POSITIVE — crypt_format() a real header onto a fresh 16 MiB file, then crypt_load() it and
 *              assert the parser ACCEPTS it (rc == 0).
 *   NEGATIVE — overwrite the on-disk magic with garbage, then crypt_load() and assert the parser
 *              REJECTS it (rc != 0).
 *
 * Prints one "PASS <name>" / "FAIL <name>" line per check and exits non-zero if any check failed.
 * A no-op or "always return 0" patch to the loader fails the NEGATIVE checks; a patch that breaks
 * header construction/parsing fails the POSITIVE checks. mayhem/test.sh parses these lines to CTRF.
 */
#include <libcryptsetup.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#define IMG_SIZE (16ULL * 1024 * 1024)

static int n_pass = 0, n_fail = 0;

static void report(const char *name, int ok)
{
	if (ok) { printf("PASS %s\n", name); n_pass++; }
	else    { printf("FAIL %s\n", name); n_fail++; }
}

/* Create a fresh 16 MiB file at path. Returns 0 on success. */
static int make_blank(const char *path)
{
	int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return -1;
	if (ftruncate(fd, (off_t)IMG_SIZE)) { close(fd); return -1; }
	close(fd);
	return 0;
}

/* Format a real LUKS header (type = CRYPT_LUKS1 / CRYPT_LUKS2) onto path. */
static int format_header(const char *path, const char *type)
{
	struct crypt_device *cd = NULL;
	struct crypt_params_luks2 p2 = { .sector_size = 512 };
	int r;

	if (crypt_init(&cd, path))
		return -1;
	r = crypt_format(cd, type, "aes", "xts-plain64", NULL, NULL, 32,
			 strcmp(type, CRYPT_LUKS2) == 0 ? &p2 : NULL);
	crypt_free(cd);
	return r;
}

/* crypt_load the requested type; returns its rc (0 == accepted). */
static int load_header(const char *path, const char *type)
{
	struct crypt_device *cd = NULL;
	int r;

	if (crypt_init(&cd, path))
		return -1;
	r = crypt_load(cd, type, NULL);
	crypt_free(cd);
	return r;
}

/*
 * Smash the on-disk magic at the primary header (offset 0) AND at every LUKS2 secondary-header
 * candidate offset (LUKS2_HDR2_OFFSETS), so the loader cannot fall back to a backup copy. LUKS1
 * has only the primary header; the extra writes are harmless. This makes the negative check robust:
 * crypt_load must reject because no valid magic remains anywhere it scans.
 */
static int corrupt_magic(const char *path)
{
	int fd = open(path, O_RDWR);
	const char junk[8] = { 'X','X','X','X','X','X','X','X' };
	/* offset 0 = primary; the rest are the LUKS2 secondary-header scan offsets. */
	const off_t offs[] = { 0, 0x04000, 0x08000, 0x10000, 0x20000,
			       0x40000, 0x80000, 0x100000, 0x200000, 0x400000 };
	size_t i;

	if (fd < 0)
		return -1;
	for (i = 0; i < sizeof(offs) / sizeof(offs[0]); i++) {
		if (pwrite(fd, junk, sizeof(junk), offs[i]) != (ssize_t)sizeof(junk)) {
			close(fd);
			return -1;
		}
	}
	close(fd);
	return 0;
}

static void check_type(const char *type, const char *posname, const char *negname)
{
	char tmpl[] = "/tmp/crypt-oracle.XXXXXX";
	int fd = mkstemp(tmpl);
	if (fd < 0) { report(posname, 0); report(negname, 0); return; }
	close(fd);

	if (make_blank(tmpl) || format_header(tmpl, type) != 0) {
		report(posname, 0);   /* could not build a valid header */
		report(negname, 0);
		unlink(tmpl);
		return;
	}

	/* POSITIVE: a freshly formatted header must load. */
	report(posname, load_header(tmpl, type) == 0);

	/* NEGATIVE: a header with a smashed magic must NOT load. */
	if (corrupt_magic(tmpl) == 0)
		report(negname, load_header(tmpl, type) != 0);
	else
		report(negname, 0);

	unlink(tmpl);
}

int main(void)
{
	crypt_set_log_callback(NULL, NULL, NULL);

	check_type(CRYPT_LUKS1, "luks1_valid_header_loads", "luks1_corrupt_magic_rejected");
	check_type(CRYPT_LUKS2, "luks2_valid_header_loads", "luks2_corrupt_magic_rejected");

	printf("ORACLE passed=%d failed=%d\n", n_pass, n_fail);
	return n_fail == 0 ? 0 : 1;
}

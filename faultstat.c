/*
 * Copyright (C) 2014-2019 Canonical, Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * Author: Colin Ian King <colin.king@canonical.com>
 */
#define _GNU_SOURCE
#define _XOPEN_SOURCE_EXTENDED

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <ctype.h>
#include <pwd.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <ncurses.h>
#include <math.h>
#include <locale.h>

#define UNAME_HASH_TABLE_SIZE	(521)
#define PROC_HASH_TABLE_SIZE 	(503)

#define OPT_CMD_SHORT		(0x00000001)
#define OPT_CMD_LONG		(0x00000002)
#define OPT_CMD_COMM		(0x00000004)
#define OPT_CMD_ALL		(OPT_CMD_SHORT | OPT_CMD_LONG | OPT_CMD_COMM)
#define OPT_DIRNAME_STRIP	(0x00000008)
#define OPT_TOP			(0x00000010)
#define OPT_TOP_TOTAL		(0x00000020)
#define OPT_ARROW		(0x00000040)

#define SORT_MAJOR_MINOR	(0x00)
#define SORT_MAJOR		(0x01)
#define SORT_MINOR		(0x02)
#define SORT_D_MAJOR_MINOR	(0x03)
#define SORT_D_MAJOR		(0x04)
#define SORT_D_MINOR		(0x05)
#define SORT_SWAP		(0x06)
#define SORT_END		(0x07)

#define ATTR_MAJOR		(0x00)
#define ATTR_MINOR		(0x01)
#define ATTR_D_MAJOR		(0x02)
#define ATTR_D_MINOR		(0x03)
#define ATTR_SWAP		(0x04)
#define ATTR_MAX		(0x05)

#define SIZEOF_ARRAY(a)		(sizeof(a) / sizeof(a[0]))

typedef struct {
	bool	attr[ATTR_MAX];
} attr_vals_t;

/* process specific information */
typedef struct proc_info {
	struct proc_info *next;		/* next in hash */
	char		*cmdline;	/* Process name from cmdline */
	pid_t		pid;		/* PID */
	bool		kernel_thread;	/* true if process is kernel thread */
} proc_info_t;

/* UID cache */
typedef struct uname_cache_t {
	struct uname_cache_t *next;
	char *		name;		/* User name */
	uid_t		uid;		/* User UID */
} uname_cache_t;

/* page fault information per process */
typedef struct fault_info_t {
	pid_t		pid;		/* process id */
	uid_t		uid;		/* process' UID */
	proc_info_t 	*proc;		/* cached process info */
	uname_cache_t	*uname;		/* cached uname info */

	int64_t		min_fault;	/* minor page faults */
	int64_t		maj_fault;	/* major page faults */
	int64_t		vm_swap;	/* pages swapped */
	int64_t		d_min_fault;	/* delta in minor page faults */
	int64_t		d_maj_fault;	/* delta in major page faults */

	struct fault_info_t *d_next;	/* sorted deltas by total */
	struct fault_info_t *s_next;	/* sorted by total */
	struct fault_info_t *next;	/* for free list */
	bool		alive;		/* true if proc is alive */
} fault_info_t;

typedef struct pid_list {
	struct pid_list	*next;		/* next in list */
	char 		*name;		/* process name */
	pid_t		pid;		/* process id */
} pid_list_t;

typedef struct {
	void (*df_setup)(void);		/* display setup */
	void (*df_endwin)(void);	/* display end */
	void (*df_clear)(void);		/* display clear */
	void (*df_refresh)(void);	/* display refresh */
	void (*df_winsize)(const bool redo);	/* display get size */
	void (*df_printf)(const char *str, ...) __attribute__((format(printf, 1, 2)));
	void (*df_attrset)(const int attr);	/* display attribute */
} display_funcs_t;

static uname_cache_t *uname_cache[UNAME_HASH_TABLE_SIZE];
static proc_info_t *proc_cache_hash[PROC_HASH_TABLE_SIZE];
static const char *const app_name = "faultstat";

static bool stop_faultstat = false;	/* set by sighandler */
static unsigned int opt_flags;		/* options */
static fault_info_t *fault_info_cache;	/* cache of fault infos */
static pid_list_t *pids;		/* PIDs to check against */
static display_funcs_t df;		/* display functions */
static bool resized;			/* true when SIGWINCH occurs */
static int rows = 25;			/* display rows */
static int cols = 80;			/* display columns */
static int cury = 0;			/* current display y position */
static int sort_by = SORT_MAJOR_MINOR;	/* sort order */

static void faultstat_top_printf(const char *fmt, ...) \
	__attribute__((format(printf, 1, 2)));

static void faultstat_normal_printf(const char *fmt, ...) \
	__attribute__((format(printf, 1, 2)));

/*
 *  sort_by to column attribute highlighting mappings
 */
static const attr_vals_t attr_vals[] = {
	/*  Major  Minor  dMajor dMinor Swap */
	{ { true,  true,  false, false, false } },
	{ { true,  false, false, false, false } },
	{ { false, true,  false, false, false } },
	{ { false, false, true,  true,  false } },
	{ { false, false, true,  false, false } },
	{ { false, false, false, true,  false } },
	{ { false, false, false, false, true  } },
};

/*
 *  Attempt to catch a range of signals so
 *  we can clean
 */
static const int signals[] = {
	/* POSIX.1-1990 */
#ifdef SIGHUP
	SIGHUP,
#endif
#ifdef SIGINT
	SIGINT,
#endif
#ifdef SIGQUIT
	SIGQUIT,
#endif
#ifdef SIGFPE
	SIGFPE,
#endif
#ifdef SIGTERM
	SIGTERM,
#endif
#ifdef SIGUSR1
	SIGUSR1,
#endif
#ifdef SIGUSR2
	SIGUSR2,
	/* POSIX.1-2001 */
#endif
#ifdef SIGXCPU
	SIGXCPU,
#endif
#ifdef SIGXFSZ
	SIGXFSZ,
#endif
	/* Linux various */
#ifdef SIGIOT
	SIGIOT,
#endif
#ifdef SIGSTKFLT
	SIGSTKFLT,
#endif
#ifdef SIGPWR
	SIGPWR,
#endif
#ifdef SIGINFO
	SIGINFO,
#endif
#ifdef SIGVTALRM
	SIGVTALRM,
#endif
	-1,
};

/*
 *  pid_max_digits()
 *	determine (or guess) maximum digits of pids
 */
static int pid_max_digits(void)
{
	static int max_digits;
	ssize_t n;
	int fd;
	const int default_digits = 6;
	const int min_digits = 5;
	char buf[32];

	if (max_digits)
		goto ret;

	max_digits = default_digits;
	fd = open("/proc/sys/kernel/pid_max", O_RDONLY);
	if (fd < 0)
		goto ret;
	n = read(fd, buf, sizeof(buf) - 1);
	(void)close(fd);
	if (n < 0)
		goto ret;

	buf[n] = '\0';
	max_digits = 0;
	while (buf[max_digits] >= '0' && buf[max_digits] <= '9')
		max_digits++;
	if (max_digits < min_digits)
		max_digits = min_digits;
ret:
	return max_digits;

}

static int getattr(const int attr)
{
	if (sort_by < 0 || sort_by >= SORT_END)
		return A_NORMAL;
	if (attr < 0 || attr >= ATTR_MAX)
		return A_NORMAL;

	return attr_vals[sort_by].attr[attr] ? A_UNDERLINE : A_NORMAL;
}


/*
 *  handle_sigwinch()
 *      flag window resize on SIGWINCH
 */
static void handle_sigwinch(int sig)
{
	(void)sig;

	resized = true;
}

/*
 *  faultstat_noop()
 *	no-operation display handler
 */
static void faultstat_noop(void)
{
}

/*
 *  faultstat_top_setup()
 *	setup display for ncurses top mode
 */
static void faultstat_top_setup(void)
{
	(void)initscr();
	(void)cbreak();
	(void)noecho();
	(void)nodelay(stdscr, 1);
	(void)keypad(stdscr, 1);
	(void)curs_set(0);
}

/*
 *  faultstat_top_endwin()
 *	end display for ncurses top mode
 */
static void faultstat_top_endwin(void)
{
	df.df_winsize(true);
	(void)resizeterm(rows, cols);
	(void)refresh();
	resized = false;
	(void)clear();
	(void)endwin();
}

/*
 *  faultstat_top_clear()
 *	clear display for ncurses top mode
 */
static void faultstat_top_clear(void)
{
	(void)clear();
}

/*
 *  faultstat_top_refresh()
 *	refresh display for ncurses top mode
 */
static void faultstat_top_refresh(void)
{
	(void)refresh();
}

/*
 *  faultstat_generic_winsize()
 *	get tty size in all modes
 */
static void faultstat_generic_winsize(const bool redo)
{
	if (redo) {
		struct winsize ws;

		if ((ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)) {
			rows = ws.ws_row;
			cols = ws.ws_col;
		} else {
			rows = 25;
			cols = 80;
		}
	}
}

/*
 *  faultstat_top_winsize()
 *	get tty size in top mode
 */
static void faultstat_top_winsize(const bool redo)
{
	(void)redo;

	faultstat_generic_winsize(true);
	(void)resizeterm(rows, cols);
}

/*
 *  faultstat_top_printf
 *	print text to display width in top mode
 */
static void faultstat_top_printf(const char *fmt, ...)
{
	va_list ap;
	char buf[256];
	int sz = sizeof(buf) - 1;

	if (cury >= rows)
		return;

	if (cols < sz)
		sz = cols;

	va_start(ap, fmt);
	(void)vsnprintf(buf, sizeof(buf), fmt, ap);
	buf[sz] = '\0';
	(void)printw(buf);
	va_end(ap);
}

/*
 *  faultstat_normal_printf
 *	normal tty printf
 */
static void faultstat_normal_printf(const char *fmt, ...)
{
	va_list ap;
	char buf[256];

	va_start(ap, fmt);
	(void)vsnprintf(buf, sizeof(buf), fmt, ap);
	(void)fputs(buf, stdout);
	va_end(ap);
}

static void faultstat_top_attrset(const int attr)
{
	attrset(attr);
}

static void faultstat_normal_attrset(const int attr)
{
	(void)attr;
}

/* ncurses based "top" mode display functions */
static const display_funcs_t df_top = {
	faultstat_top_setup,
	faultstat_top_endwin,
	faultstat_top_clear,
	faultstat_top_refresh,
	faultstat_top_winsize,
	faultstat_top_printf,
	faultstat_top_attrset,
};

/* normal tty mode display functions */
static const display_funcs_t df_normal = {
	faultstat_noop,
	faultstat_noop,
	faultstat_noop,
	faultstat_noop,
	faultstat_generic_winsize,
	faultstat_normal_printf,
	faultstat_normal_attrset,
};

/*
 *  display_restore()
 *	restore display back to normal tty
 */
static void display_restore(void)
{
	df.df_endwin();
	df = df_normal;
}

/*
 *  out_of_memory()
 *      report out of memory condition
 */
static void out_of_memory(const char *msg)
{
	display_restore();
	(void)fprintf(stderr, "Out of memory: %s.\n", msg);
}

/*
 *  uname_name()
 *	fetch name from uname, handle
 *	unknown NULL unames too
 */
static inline const char *uname_name(const uname_cache_t * const uname)
{
	return uname ? uname->name : "<unknown>";
}

/*
 *  count_bits()
 */
#if defined(__GNUC__)
/*
 *  use GCC built-in
 */
static inline unsigned int count_bits(const unsigned int val)
{
	return __builtin_popcount(val);
}
#else
/*
 *  count bits set, from C Programming Language 2nd Ed
 */
static inline unsigned int OPTIMIZE3 HOT count_bits(const unsigned int val)
{
	register unsigned int c, n = val;

	for (c = 0; n; c++)
		n &= n - 1;

	return c;
}
#endif

/*
 *  int64_to_str()
 *	report int64 values in different units
 */
static void int64_to_str(int64_t val, char *buf, const size_t buflen)
{
	double s;
	const int64_t pos_val = val < 0 ? 0 : val;
	const double v = (double)pos_val;
	char unit;

	(void)memset(buf, 0, buflen);

	if (pos_val < 1000000LL) {
		s = v;
		unit = ' ';
	} else if (pos_val < 1000000000LL) {
		s = v / 1000.0;
		unit = 'k';
	} else if (pos_val < 1000000000000LL) {
		s = v / 1000000.0;
		unit = 'M';
	} else {
		s = v / 1000000000.0;
		unit = 'G';
	}
	(void)snprintf(buf, buflen, "%6.0f%c", s, unit);
}

/*
 *  get_pid_comm
 *	get comm name of a pid
 */
static char *get_pid_comm(const pid_t pid)
{
	char buffer[4096];
	int fd;
	ssize_t ret;

	(void)snprintf(buffer, sizeof(buffer), "/proc/%i/comm", pid);

	if ((fd = open(buffer, O_RDONLY)) < 0)
		return NULL;

	if ((ret = read(fd, buffer, sizeof(buffer))) <= 0) {
		(void)close(fd);
		return NULL;
	}
	(void)close(fd);
	buffer[ret - 1] = '\0';

	return strdup(buffer);
}

/*
 *  get_pid_cmdline
 * 	get process's /proc/pid/cmdline
 */
static char *get_pid_cmdline(const pid_t pid)
{
	char buffer[4096];
	char *ptr;
	int fd;
	ssize_t ret;

	(void)snprintf(buffer, sizeof(buffer), "/proc/%i/cmdline", pid);

	if ((fd = open(buffer, O_RDONLY)) < 0)
		return NULL;

	if ((ret = read(fd, buffer, sizeof(buffer))) <= 0) {
		(void)close(fd);
		return NULL;
	}
	(void)close(fd);

	if (ret >= (ssize_t)sizeof(buffer))
		ret = sizeof(buffer) - 1;
	buffer[ret] = '\0';

	/*
	 *  OPT_CMD_LONG option we get the full cmdline args
	 */
	if (opt_flags & OPT_CMD_LONG) {
		for (ptr = buffer; ptr < buffer + ret - 1; ptr++) {
			if (*ptr == '\0')
				*ptr = ' ';
		}
		*ptr = '\0';
	}
	/*
	 *  OPT_CMD_SHORT option we discard anything after a space
	 */
	if (opt_flags & OPT_CMD_SHORT) {
		for (ptr = buffer; *ptr && (ptr < buffer + ret); ptr++) {
			if (*ptr == ' ')
				*ptr = '\0';
		}
	}

	if (opt_flags & OPT_DIRNAME_STRIP) {
		char *base = buffer;

		for (ptr = buffer; *ptr; ptr++) {
			if (isblank(*ptr))
				break;
			if (*ptr == '/')
				base = ptr + 1;
		}
		return strdup(base);
	}

	return strdup(buffer);
}

/*
 *  pid_exists()
 *	true if given process with given pid exists
 */
static bool pid_exists(const pid_t pid)
{
	char path[PATH_MAX];
	struct stat statbuf;

	(void)snprintf(path, sizeof(path), "/proc/%i", pid);
	return stat(path, &statbuf) == 0;
}

/*
 *  proc_cache_hash_pid()
 *	hash a process id
 */
static inline unsigned long proc_cache_hash_pid(const pid_t pid)
{
	const unsigned long h = (unsigned long)pid;

	return h % PROC_HASH_TABLE_SIZE;
}

/*
 *  proc_cache_add_at_hash_index()
 *	helper function to add proc info to the proc cache and list
 */
static proc_info_t *proc_cache_add_at_hash_index(
	const unsigned long h,
	const pid_t pid)
{
	proc_info_t *p;

	if ((p = calloc(1, sizeof(*p))) == NULL) {
		out_of_memory("allocating proc cache");
		return NULL;
	}

	p->pid = pid;
	p->cmdline = get_pid_cmdline(pid);
	if (p->cmdline == NULL)
		p->kernel_thread = true;

	if ((p->cmdline == NULL) || (opt_flags & OPT_CMD_COMM))
		p->cmdline = get_pid_comm(pid);
	p->next = proc_cache_hash[h];
	proc_cache_hash[h] = p;

	return p;
}

/*
 *  proc_cache_find_by_pid()
 *	find process info by the process id, if it is not found
 * 	and it is a traceable process then cache it
 */
static proc_info_t *proc_cache_find_by_pid(const pid_t pid)
{
	const unsigned long h = proc_cache_hash_pid(pid);
	proc_info_t *p;

	for (p = proc_cache_hash[h]; p; p = p->next)
		if (p->pid == pid)
			return p;

	/*
	 *  Not found, so add it and return it if it is a legitimate
	 *  process to trace
	 */
	if (!pid_exists(pid))
		return NULL;

	return proc_cache_add_at_hash_index(h, pid);
}

/*
 *  proc_cache_cleanup()
 *	free up proc cache hash table
 */
static void proc_cache_cleanup(void)
{
	size_t i;

	for (i = 0; i < PROC_HASH_TABLE_SIZE; i++) {
		proc_info_t *p = proc_cache_hash[i];

		while (p) {
			proc_info_t *next = p->next;

			free(p->cmdline);
			free(p);

			p = next;
		}
	}
}

/*
 *  timeval_to_double
 *      timeval to a double
 */
static inline double timeval_to_double(const struct timeval * const tv)
{
	return (double)tv->tv_sec + ((double)tv->tv_usec / 1000000.0);
}

/*
 *  double_to_timeval
 *      seconds in double to timeval
 */
static inline void double_to_timeval(
	const double val,
	struct timeval * const tv)
{
	tv->tv_sec = val;
	tv->tv_usec = (val - (time_t)val) * 1000000.0;
}

/*
 *  gettime_to_double()
 *      get time as a double
 */
static double gettime_to_double(void)
{
	struct timeval tv;

	if (gettimeofday(&tv, NULL) < 0) {
		display_restore();
		(void)fprintf(stderr, "gettimeofday failed: errno=%d (%s)\n",
			errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	return timeval_to_double(&tv);
}

static inline unsigned long hash_uid(const uid_t uid)
{
        const unsigned long h = (unsigned long)uid;

        return h % UNAME_HASH_TABLE_SIZE;
}

/*
 *  uname_cache_find()
 *	lookup uname info on uid and cache data
 */
static uname_cache_t *uname_cache_find(const uid_t uid)
{
	struct passwd *pw;
	uname_cache_t *uname;
	const unsigned long h = hash_uid(uid);

	for (uname = uname_cache[h]; uname; uname = uname->next) {
		if (uname->uid == uid)
			return uname;
	}

	if ((uname = calloc(1, sizeof(*uname))) == NULL) {
		out_of_memory("allocating pwd cache item");
		return NULL;
	}

	if ((pw = getpwuid(uid)) == NULL) {
		char buf[16];

		(void)snprintf(buf, sizeof(buf), "%i", uid);
		uname->name = strdup(buf);
	} else {
		uname->name = strdup(pw->pw_name);
	}

	if (uname->name == NULL) {
		out_of_memory("allocating pwd cache item");
		free(uname);
		return NULL;
	}

	uname->uid = uid;
	uname->next = uname_cache[h];
	uname_cache[h] = uname;

	return uname;
}

/*
 *  uname_cache_cleanup()
 *	free cache
 */
static void uname_cache_cleanup(void)
{
	size_t i;

	for (i = 0; i < UNAME_HASH_TABLE_SIZE; i++) {
		uname_cache_t *u = uname_cache[i];

		while (u) {
			uname_cache_t *next = u->next;

			free(u->name);
			free(u);
			u = next;
		}
	}
}

/*
 *  fault_cache_alloc()
 *	allocate a fault_info_t, first try the cache of
 *	unused fault_info's, if none available fall back
 *	to calloc
 */
static fault_info_t *fault_cache_alloc(void)
{
	fault_info_t *fault_info;

	if (fault_info_cache) {
		fault_info = fault_info_cache;
		fault_info_cache = fault_info_cache->next;

		(void)memset(fault_info, 0, sizeof(*fault_info));
		return fault_info;
	}

	if ((fault_info = calloc(1, sizeof(*fault_info))) == NULL) {
		out_of_memory("allocating page fault tracking information");
		return NULL;
	}
	return fault_info;
}

/*
 *  fault_cache_free()
 *	free a fault_info_t by just adding it to the
 *	fault_info_cache free list
 */
static inline void fault_cache_free(fault_info_t * const fault_info)
{
	fault_info->next = fault_info_cache;
	fault_info_cache = fault_info;
}

/*
 *  fault_cache_free_list()
 *	free up a list of fault_info_t items by
 *	adding them to the fault_info_cache free list
 */
static void fault_cache_free_list(fault_info_t *fault_info)
{
	while (fault_info) {
		fault_info_t *next = fault_info->next;

		fault_cache_free(fault_info);
		fault_info = next;
	}
}

/*
 *  fault_cache_prealloc()
 *	create some spare fault_info_t items on
 *	the free list so that we don't keep on
 *	hitting the heap during the run
 */
static void fault_cache_prealloc(const size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		fault_info_t *fault_info;

		if ((fault_info = calloc(1, sizeof(*fault_info))) != NULL)
			fault_cache_free_list(fault_info);
	}
}

/*
 *  fault_cache_cleanup()
 *	free the fault_info_cache free list
 */
static void fault_cache_cleanup(void)
{
	while (fault_info_cache) {
		fault_info_t *next = fault_info_cache->next;

		free(fault_info_cache);
		fault_info_cache = next;
	}
}

/*
 *  fault_get_by_proc()
 *	get page fault info for a specific proc
 */
static int fault_get_by_proc(const pid_t pid, fault_info_t ** const fault_info)
{
	FILE *fp;
	fault_info_t *new_fault_info;
	proc_info_t *proc;
	unsigned long min_fault, maj_fault, vm_swap;
	int n;
	char buffer[4096];
	char path[PATH_MAX];
	int got_fields = 0;

	if (getpgid(pid) == 0)
		return 0;	/* Kernel thread */

	if ((proc = proc_cache_find_by_pid(pid)) == NULL)
		return 0;	/* It died before we could get info */

	if (proc->kernel_thread)
		return 0;	/* Ignore */

	if (pids) {
		pid_list_t *p;
		char *tmp = basename(proc->cmdline);

		for (p = pids; p; p = p->next) {
			if (p->pid == pid)
				break;
			if (p->name && strcmp(p->name, tmp) == 0)
				break;
		}
		if (!p)
			return 0;
	}

	if ((new_fault_info = fault_cache_alloc()) == NULL)
		return -1;

	(void)snprintf(path, sizeof(path), "/proc/%i/stat", pid);
	if ((fp = fopen(path, "r")) == NULL)
		return -1;	/* Gone? */
	n = fscanf(fp, "%*d %*s %*c %*d %*d %*d %*d %*d %*u %lu %*u %lu",
		&min_fault, &maj_fault);
	if (n == 2) {
		new_fault_info->min_fault = min_fault;
		new_fault_info->maj_fault = maj_fault;
	}
	(void)fclose(fp);

	new_fault_info->pid = pid;
	new_fault_info->proc = proc_cache_find_by_pid(pid);
	new_fault_info->uid = 0;
	new_fault_info->uname = NULL;
	new_fault_info->next = *fault_info;
	*fault_info = new_fault_info;

	(void)snprintf(path, sizeof(path), "/proc/%i/status", pid);
	if ((fp = fopen(path, "r")) == NULL)
		return 0;

	/*
	 *  Find Uid and uname. Note that it may
	 *  not be found, in which case new->uname is
	 *  still NULL, so we need to always use
	 *  uname_name() to fetch the uname to handle
	 *  the NULL uname cases.
	 */
	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		if (!strncmp(buffer, "VmSwap:", 7)) {
			if (sscanf(buffer + 8, "%lu", &vm_swap) == 1)
				new_fault_info->vm_swap = vm_swap;
			got_fields++;
		} else if (!strncmp(buffer, "Uid:", 4)) {
			if (sscanf(buffer + 5, "%9i", &new_fault_info->uid) == 1) {
				new_fault_info->uname = uname_cache_find(new_fault_info->uid);
				if (new_fault_info->uname == NULL) {
					(void)fclose(fp);
					return -1;
				}
			}
			got_fields++;
		}
		if (got_fields == 2)
			break;
	}
	(void)fclose(fp);

	return 0;
}

/*
 *  fault_get_all_pids()
 *	scan processes for page fault info
 */
static int fault_get_all_pids(fault_info_t ** const fault_info, size_t * const npids)
{
	DIR *dir;
	struct dirent *entry;
	*npids = 0;

	if ((dir = opendir("/proc")) == NULL) {
		display_restore();
		(void)fprintf(stderr, "Cannot read directory /proc\n");
		return -1;
	}

	while ((entry = readdir(dir)) != NULL) {
		pid_t pid;

		if (!isdigit(entry->d_name[0]))
			continue;
		pid = (pid_t)strtoul(entry->d_name, NULL, 10);

		if (fault_get_by_proc(pid, fault_info) < 0) {
			(void)closedir(dir);
			return -1;
		}
		(*npids)++;
	}

	(void)closedir(dir);

	return 0;
}


/*
 *  fault_delta()
 *	compute page fault changes
 */
static void fault_delta(fault_info_t * const fault_new, fault_info_t *const fault_old_list)
{
	fault_info_t *fault_old;

	for (fault_old = fault_old_list; fault_old; fault_old = fault_old->next) {
		if (fault_new->pid == fault_old->pid) {
			fault_new->d_min_fault = fault_new->min_fault - fault_old->min_fault;
			fault_new->d_maj_fault = fault_new->maj_fault - fault_old->maj_fault;
			fault_old->alive = true;
			return;
		}
	}
	fault_new->d_min_fault = fault_new->min_fault;
	fault_new->d_maj_fault = fault_new->maj_fault;
}

/*
 *  get_cmdline()
 *	get command line if it is defined
 */
static inline char *get_cmdline(const fault_info_t * const fault_info)
{
	if (fault_info->proc && fault_info->proc->cmdline)
		return fault_info->proc->cmdline;

	return "<unknown>";
}

static bool compare(fault_info_t *f1, fault_info_t *f2)
{
	switch (sort_by) {
	case SORT_MAJOR_MINOR:
		return f1->min_fault + f1->maj_fault <
		       f2->min_fault + f2->maj_fault;
		break;
	case SORT_MAJOR:
		return f1->maj_fault < f2->maj_fault;
		break;
	case SORT_MINOR:
		return f1->min_fault < f2->min_fault;
		break;
	case SORT_D_MAJOR_MINOR:
		return f1->d_min_fault + f1->d_maj_fault <
		       f2->d_min_fault + f2->d_maj_fault;
		break;
	case SORT_D_MAJOR:
		return f1->d_maj_fault < f2->d_maj_fault;
		break;
	case SORT_D_MINOR:
		return f1->d_min_fault < f2->d_min_fault;
		break;
	case SORT_SWAP:
		return f1->vm_swap < f2->vm_swap;
		break;
	default:
		break;
	}
	return true;
}

static void fault_heading(const bool one_shot, const int pid_size)
{
	if (one_shot) {
		df.df_printf(" %*.*s  Major   Minor    Swap  User       Command\n",
			pid_size, pid_size, "PID");
	} else {
		df.df_attrset(A_BOLD);
		df.df_printf(" %*.*s  ", pid_size, pid_size, "PID");
		df.df_attrset(getattr(ATTR_MAJOR) | A_BOLD);
		df.df_printf("Major");
		df.df_attrset(A_NORMAL);
		df.df_printf("   ");
		df.df_attrset(getattr(ATTR_MINOR) | A_BOLD);
		df.df_printf("Minor");
		df.df_attrset(A_NORMAL);
		df.df_printf("  ");
		df.df_attrset(getattr(ATTR_D_MAJOR) | A_BOLD);
		df.df_printf("+Major");
		df.df_attrset(A_NORMAL);
		df.df_printf("  ");
		df.df_attrset(getattr(ATTR_D_MINOR) | A_BOLD);
		df.df_printf("+Major");
		df.df_attrset(A_NORMAL);
		df.df_printf("    ");
		df.df_attrset(getattr(ATTR_SWAP) | A_BOLD);
		df.df_printf("Swap");
		df.df_attrset(A_BOLD);
		df.df_printf("  %sUser       Command\n", (opt_flags & OPT_ARROW) ? "D " : "");
		df.df_attrset(A_NORMAL);
	}
}

/*
 *  fault_dump()
 *	dump out page fault usage
 */
static int fault_dump(
	fault_info_t * const fault_info_old,
	fault_info_t * const fault_info_new,
	const bool one_shot)
{
	fault_info_t *fault_info, **l;
	fault_info_t *sorted = NULL;
	int64_t	t_min_fault = 0, t_maj_fault = 0;
	int64_t	t_d_min_fault = 0, t_d_maj_fault = 0;
	const int pid_size = pid_max_digits();
	char s_min_fault[12], s_maj_fault[12],
	     s_d_min_fault[12], s_d_maj_fault[12],
	     s_vm_swap[12];

	for (fault_info = fault_info_new; fault_info; fault_info = fault_info->next) {
		fault_delta(fault_info, fault_info_old);
		for (l = &sorted; *l; l = &(*l)->s_next) {
			if (compare(*l, fault_info)) {
				fault_info->s_next = (*l);
				break;
			}
		}
		*l = fault_info;

		t_min_fault += fault_info->min_fault;
		t_maj_fault += fault_info->maj_fault;

		t_d_min_fault += fault_info->d_min_fault;
		t_d_maj_fault += fault_info->d_maj_fault;
	}

	for (fault_info = fault_info_old; fault_info; fault_info = fault_info->next) {
		if (fault_info->alive)
			continue;

		/* Process has died, so include it as -ve delta */
		for (l = &sorted; *l; l = &(*l)->d_next) {
			if (compare(*l, fault_info)) {
				fault_info->d_next = (*l);
				break;
			}
		}
		*l = fault_info;

		t_min_fault += fault_info->min_fault;
		t_maj_fault += fault_info->maj_fault;

		fault_info->d_min_fault = -fault_info->min_fault;
		fault_info->d_maj_fault = -fault_info->maj_fault;

		t_d_min_fault += fault_info->d_min_fault;
		t_d_maj_fault += fault_info->d_maj_fault;

		fault_info->min_fault = 0;
		fault_info->maj_fault = 0;
	}

	fault_heading(one_shot, pid_size);
	for (fault_info = sorted; fault_info; fault_info = fault_info->s_next) {
		const char *cmd = get_cmdline(fault_info);

		int64_t delta = fault_info->d_min_fault + fault_info->d_maj_fault;
		const char * const arrow = (delta < 0) ? "\u2193 " :
						  ((delta > 0) ? "\u2191 "  : "  ");

		int64_to_str(fault_info->maj_fault, s_maj_fault, sizeof(s_maj_fault));
		int64_to_str(fault_info->min_fault, s_min_fault, sizeof(s_min_fault));
		int64_to_str(fault_info->vm_swap, s_vm_swap, sizeof(s_vm_swap));
		if (one_shot) {
			df.df_printf(" %*d %7s %7s %7s %-10.10s %s\n",
				pid_size, fault_info->pid,
				s_maj_fault, s_min_fault, s_vm_swap,
				uname_name(fault_info->uname), cmd);
		} else {
			int64_to_str(fault_info->d_maj_fault, s_d_maj_fault, sizeof(s_d_maj_fault));
			int64_to_str(fault_info->d_min_fault, s_d_min_fault, sizeof(s_d_min_fault));
			df.df_printf(" %*d %7s %7s %7s %7s %7s %s%-10.10s %s\n",
				pid_size, fault_info->pid,
				s_maj_fault, s_min_fault,
				s_d_maj_fault, s_d_min_fault,
				s_vm_swap,
				one_shot ? " " :
				(opt_flags & OPT_ARROW) ? arrow : "",
				uname_name(fault_info->uname), cmd);
		}
	}

	int64_to_str(t_maj_fault, s_maj_fault, sizeof(s_maj_fault));
	int64_to_str(t_min_fault, s_min_fault, sizeof(s_min_fault));
	if (one_shot) {
		df.df_printf("Total: %7s %7s\n\n", s_maj_fault, s_min_fault);
	} else {
		int64_to_str(t_d_maj_fault, s_d_maj_fault, sizeof(s_d_maj_fault));
		int64_to_str(t_d_min_fault, s_d_min_fault, sizeof(s_d_min_fault));
		df.df_printf("Total: %7s %7s %7s %7s\n\n", 
			s_maj_fault, s_min_fault, s_d_maj_fault, s_d_min_fault);
	}

	return 0;
}

/*
 *  fault_dump_diff()
 *	dump differences between old and new events
 */
static int fault_dump_diff(
	fault_info_t * const fault_info_old,
	fault_info_t * const fault_info_new)
{
	fault_info_t *fault_info, **l;
	fault_info_t *sorted_deltas = NULL;
	int64_t	t_min_fault = 0, t_maj_fault = 0;
	int64_t	t_d_min_fault = 0, t_d_maj_fault = 0;
	const int pid_size = pid_max_digits();
	char s_min_fault[12], s_maj_fault[12],
	     s_d_min_fault[12], s_d_maj_fault[12],
	     s_vm_swap[12];

	for (fault_info = fault_info_new; fault_info; fault_info = fault_info->next) {
		fault_delta(fault_info, fault_info_old);
		if ((fault_info->d_min_fault + fault_info->d_maj_fault) == 0)
			continue;

		for (l = &sorted_deltas; *l; l = &(*l)->d_next) {
			if (compare(*l, fault_info)) {
				fault_info->d_next = (*l);
				break;
			}
		}
		*l = fault_info;

		t_min_fault += fault_info->min_fault;
		t_maj_fault += fault_info->maj_fault;

		t_d_min_fault += fault_info->d_min_fault;
		t_d_maj_fault += fault_info->d_maj_fault;
	}

	for (fault_info = fault_info_old; fault_info; fault_info = fault_info->next) {
		if (fault_info->alive)
			continue;

		/* Process has died, so include it as -ve delta */
		for (l = &sorted_deltas; *l; l = &(*l)->d_next) {
			if (compare(*l, fault_info)) {
				fault_info->d_next = (*l);
				break;
			}
		}
		*l = fault_info;

		t_min_fault -= fault_info->min_fault;
		t_maj_fault -= fault_info->maj_fault;

		fault_info->d_min_fault = -fault_info->min_fault;
		fault_info->d_maj_fault = -fault_info->maj_fault;

		t_d_min_fault += fault_info->d_min_fault;
		t_d_maj_fault += fault_info->d_maj_fault;

		fault_info->min_fault = 0;
		fault_info->maj_fault = 0;
	}

	fault_heading(false, pid_size);
	for (fault_info = sorted_deltas; fault_info; ) {
		const char *cmd = get_cmdline(fault_info);
		fault_info_t *next = fault_info->d_next;

		int64_to_str(fault_info->maj_fault, s_maj_fault, sizeof(s_maj_fault));
		int64_to_str(fault_info->min_fault, s_min_fault, sizeof(s_min_fault));
		int64_to_str(fault_info->d_maj_fault, s_d_maj_fault, sizeof(s_d_maj_fault));
		int64_to_str(fault_info->d_min_fault, s_d_min_fault, sizeof(s_d_min_fault));
		int64_to_str(fault_info->vm_swap, s_vm_swap, sizeof(s_vm_swap));

		df.df_printf(" %*d %7s %7s %7s %7s %7s %-10.10s %s\n",
			pid_size, fault_info->pid,
			s_maj_fault, s_min_fault,
			s_d_maj_fault, s_d_min_fault,
			s_vm_swap,
			uname_name(fault_info->uname), cmd);

		fault_info->d_next = NULL;	/* Nullify for next round */
		fault_info = next;
	}

	int64_to_str(t_maj_fault, s_maj_fault, sizeof(s_maj_fault));
	int64_to_str(t_min_fault, s_min_fault, sizeof(s_min_fault));
	int64_to_str(t_d_maj_fault, s_d_maj_fault, sizeof(s_d_maj_fault));
	int64_to_str(t_d_min_fault, s_d_min_fault, sizeof(s_d_min_fault));
	df.df_printf("Total: %7s %7s %7s %7s\n\n", 
		s_maj_fault, s_min_fault, s_d_maj_fault, s_d_min_fault);

	return 0;
}

/*
 *  handle_sig()
 *      catch signals and flag a stop
 */
static void handle_sig(int dummy)
{
	(void)dummy;    /* Stop unused parameter warning with -Wextra */

	stop_faultstat = true;
}

/*
 * pid_list_cleanup()
 *	free pid list
 */
static void pid_list_cleanup(void)
{
	pid_list_t *p = pids;

	while (p) {
		pid_list_t *next = p->next;
		if (p->name)
			free(p->name);
		free(p);
		p = next;
	}
}

/*
 *  parse_pid_list()
 *	parse list of process IDs,
 *	collect process info in pids list
 */
static int parse_pid_list(char * const arg)
{
	char *str, *token;
	pid_list_t *p;

	for (str = arg; (token = strtok(str, ",")) != NULL; str = NULL) {
		if (isdigit(token[0])) {
			pid_t pid;

			errno = 0;
			pid = strtol(token, NULL, 10);
			if (errno) {
				(void)fprintf(stderr, "Invalid pid specified.\n");
				pid_list_cleanup();
				return -1;
			}
			for (p = pids; p; p = p->next) {
				if (p->pid == pid)
					break;
			}
			if (!p) {
				if ((p = calloc(1, sizeof(*p))) == NULL)
					goto nomem;
				p->pid = pid;
				p->name = NULL;
				p->next = pids;
				pids = p;
			}
		} else {
			if ((p = calloc(1, sizeof(*p))) == NULL)
				goto nomem;
			if ((p->name = strdup(token)) == NULL) {
				free(p);
				goto nomem;
			}
			p->pid = 0;
			p->next = pids;
			pids = p;
		}
	}

	return 0;
nomem:
	out_of_memory("allocating pid list.\n");
	pid_list_cleanup();
	return -1;
}

/*
 *  show_usage()
 *	show how to use
 */
static void show_usage(void)
{
	(void)printf("%s, version %s\n\n"
		"Usage: %s [options] [duration] [count]\n"
		"Options are:\n"
		"  -a\t\tshow page fault change with up/down arrows\n"
		"  -c\t\tget command name from processes comm field\n"
		"  -d\t\tstrip directory basename off command information\n"
		"  -h\t\tshow this help information\n"
		"  -l\t\tshow long (full) command information\n"
		"  -p proclist\tspecify comma separated list of processes to monitor\n"
		"  -s\t\tshow short command information\n"
		"  -t\t\ttop mode, show only changes in page faults\n"
		"  -T\t\ttop mode, show top page faulters\n",
		app_name, VERSION, app_name);
}

int main(int argc, char **argv)
{
	fault_info_t *fault_info_old = NULL;
	fault_info_t *fault_info_new = NULL;

	double duration = 1.0;
	struct timeval tv1;
	bool forever = true;
	long int count = 0;
	size_t npids;

	df = df_normal;

	for (;;) {
		int c = getopt(argc, argv, "acdhlp:stT");

		if (c == -1)
			break;
		switch (c) {
		case 'a':
			opt_flags |= OPT_ARROW;
			break;
		case 'c':
			opt_flags |= OPT_CMD_COMM;
			break;
		case 'd':
			opt_flags |= OPT_DIRNAME_STRIP;
			break;
		case 'h':
			show_usage();
			exit(EXIT_SUCCESS);
		case 'l':
			opt_flags |= OPT_CMD_LONG;
			break;
		case 'p':
			if (parse_pid_list(optarg) < 0)
				exit(EXIT_FAILURE);
			break;
		case 's':
			opt_flags |= OPT_CMD_SHORT;
			break;
		case 'T':
			opt_flags |= OPT_TOP_TOTAL;
			/* fall through */
		case 't':
			opt_flags |= OPT_TOP;
			count = -1;
			break;
		default:
			show_usage();
			exit(EXIT_FAILURE);
		}
	}

	if (count_bits(opt_flags & OPT_CMD_ALL) > 1) {
		(void)fprintf(stderr, "Cannot have -c, -l, -s at same time.\n");
		exit(EXIT_FAILURE);
	}

	setlocale(LC_ALL, "");

	if (optind < argc) {
		errno = 0;
		duration = strtof(argv[optind++], NULL);
		if (errno) {
			(void)fprintf(stderr, "Invalid or out of range value for duration\n");
			exit(EXIT_FAILURE);
		}
		if (duration < 1.0) {
			(void)fprintf(stderr, "Duration must be 1.0 or more seconds.\n");
			exit(EXIT_FAILURE);
		}
		count = -1;
	}

	if (optind < argc) {
		forever = false;
		errno = 0;
		count = strtol(argv[optind++], NULL, 10);
		if (errno) {
			(void)fprintf(stderr, "Invalid or out of range value for count\n");
			exit(EXIT_FAILURE);
		}
		if (count < 1) {
			(void)fprintf(stderr, "Count must be > 0\n");
			exit(EXIT_FAILURE);
		}
	}

	if (count == 0) {
		if (fault_get_all_pids(&fault_info_new, &npids) == 0) {
			fault_dump(fault_info_old, fault_info_new, true);
		}
	} else {
		struct sigaction new_action;
		uint64_t t = 1;
		int i;
		bool redo = false;
		double duration_secs = (double)duration, time_start, time_now;

		if (opt_flags & OPT_TOP)
			df = df_top;
		/*
		 *  Pre-cache, this way we reduce
		 *  the amount of mem infos we alloc during
		 *  sampling
		 */
		if (fault_get_all_pids(&fault_info_old, &npids) < 0)
			goto free_cache;
		fault_cache_prealloc((npids * 5) / 4);

		if (gettimeofday(&tv1, NULL) < 0) {
			(void)fprintf(stderr, "gettimeofday failed: errno=%d (%s)\n",
				errno, strerror(errno));
			exit(EXIT_FAILURE);
		}

		if (!(opt_flags & OPT_TOP))
			(void)printf("Change in page faults (average per second):\n");

		(void)memset(&new_action, 0, sizeof(new_action));
		for (i = 0; signals[i] != -1; i++) {
			new_action.sa_handler = handle_sig;
			sigemptyset(&new_action.sa_mask);
			new_action.sa_flags = 0;

			if (sigaction(signals[i], &new_action, NULL) < 0) {
				(void)fprintf(stderr, "sigaction failed: errno=%d (%s)\n",
					errno, strerror(errno));
				exit(EXIT_FAILURE);
			}
		}
		(void)memset(&new_action, 0, sizeof(new_action));
		new_action.sa_handler = handle_sigwinch;
		if (sigaction(SIGWINCH, &new_action , NULL) < 0) {
			(void)fprintf(stderr, "sigaction failed: errno=%d (%s)\n",
				errno, strerror(errno));
			exit(EXIT_FAILURE);
		}

		time_now = time_start = gettime_to_double();

		df.df_setup();
		df.df_winsize(true);

		while (!stop_faultstat && (forever || count--)) {
			struct timeval tv;
			double secs;
			int nchar;

			df.df_clear();
			cury = 0;

			/* Timeout to wait for in the future for this sample */
			secs = time_start + ((double)t * duration_secs) - time_now;
			/* Play catch-up, probably been asleep */
			if (secs < 0.0) {
				t = ceil((time_now - time_start) / duration_secs);
				secs = time_start +
					((double)t * duration_secs) - time_now;
				/* We don't get sane stats if duration is too small */
				if (secs < 0.5)
					secs += duration_secs;
			} else {
				if (!redo)
					t++;
			}
			redo = false;

			double_to_timeval(secs, &tv);
retry:
			if (select(0, NULL, NULL, NULL, &tv) < 0) {
				if (errno == EINTR) {
					if (!resized) {
						stop_faultstat = true;
					} else {
						redo = true;
						df.df_winsize(true);
						if (timeval_to_double(&tv) > 0.0)
							goto retry;
					}
				} else {
					display_restore();
					(void)fprintf(stderr, "Select failed: %s\n", strerror(errno));
					break;
				}
			}

			nchar = 0;
			if ((ioctl(0, FIONREAD, &nchar) == 0) && (nchar > 0)) {
				char ch;

				nchar = read(0, &ch, 1);
				if (nchar == 1) {
					switch (ch) {
					case 'q':
					case 'Q':
					case 27:
						stop_faultstat = true;
						break;
					case 'a':
						opt_flags ^= OPT_ARROW;
						break;
					case 't':
						opt_flags ^= OPT_TOP_TOTAL;
						break;
					case 's':
						sort_by++;
						if (sort_by >= SORT_END)
							sort_by = SORT_MAJOR_MINOR;
					}
				}
			}


			if (fault_get_all_pids(&fault_info_new, &npids) < 0)
				goto free_cache;

			if (opt_flags & OPT_TOP_TOTAL) {
				fault_dump(fault_info_old, fault_info_new, false);
			} else {
				fault_dump_diff(fault_info_old, fault_info_new);
			}
			df.df_refresh();

			fault_cache_free_list(fault_info_old);
			fault_info_old = fault_info_new;
			fault_info_new = NULL;
			time_now = gettime_to_double();
		}

free_cache:
		fault_cache_free_list(fault_info_old);
	}

	display_restore();
	uname_cache_cleanup();
	proc_cache_cleanup();
	fault_cache_cleanup();
	pid_list_cleanup();

	exit(EXIT_SUCCESS);
}

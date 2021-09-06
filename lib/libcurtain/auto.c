#include <curtain.h>
#include <dlfcn.h>
#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sysexits.h>
#include <paths.h>

static struct curtain_config *auto_curtain_cfg = NULL;

static void
auto_curtain_setup(const char *name)
{
	struct curtain_config *cfg;
	char *p;
	auto_curtain_cfg = cfg = curtain_config_new();
	cfg->unsafe_level = 1; /* XXX */
	cfg->on_exec = false;
	curtain_config_tags_from_env(cfg);
	curtain_config_tag_push(cfg, "_default");
	curtain_config_tag_push(cfg, "_basic");
	curtain_config_tag_push(cfg, "_auto");
	if (name)
		curtain_config_tag_push(cfg, name);
	if ((p = getenv("CURTAIN_AUTO_X11"))) {
		curtain_config_tag_push(cfg, "_x11");
		curtain_config_tag_push(cfg, "_gui");
		cfg->x11 = true;
		cfg->x11_trusted = strcmp(p, "trusted") == 0;
	}
	if (getenv("CURTAIN_AUTO_WAYLAND")) {
		curtain_config_tag_push(cfg, "_wayland");
		curtain_config_tag_push(cfg, "_gui");
		cfg->wayland = true;
	}
	curtain_config_tmpdir(cfg, true);
	curtain_config_load_tags(cfg);
	curtain_config_gui(cfg);
	curtain_enforce();
}

static void __attribute__((constructor))
auto_curtain_ctor()
{
	const int mib[] = {
		CTL_KERN,
		KERN_PROC,
		KERN_PROC_ARGS,
		-1,
	};
	char *p, *name;
	char argsbuf[1024];
	size_t argsbuf_size = sizeof argsbuf;
	int r;

	if (!getenv("CURTAIN_AUTO"))
		return;

	if (auto_curtain_cfg) {
		warnx("auto curtain constructor called multiple times!");
		return;
	}

	r = sysctl(mib, nitems(mib), argsbuf, &argsbuf_size, NULL, 0);
	if (r < 0 && errno != ENOMEM) {
		warn("sysctl");
		name = NULL;
	} else {
		argsbuf[argsbuf_size ? argsbuf_size - 1 : 0] = '\0';
		name = argsbuf;
	}

	if ((p = strrchr(name, '/')))
		name = p + 1;

	p = getenv("CURTAIN_AUTO");
	if (p) {
		p = strdup(p);
		if (!p)
			err(EX_TEMPFAIL, "strdup");
		unsetenv("CURTAIN_AUTO");
	}
	auto_curtain_setup(name);
	if (p)
		setenv("CURTAIN_AUTO", p, 1);
}

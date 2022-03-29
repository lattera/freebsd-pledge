#include <stdlib.h>

#include <err.h>

#include <curtain.h>

int
curtain_simple_sandbox(const char *tag)
{
	struct curtain_config *cfg;
	int r;
	cfg = curtain_config_new(0);
	curtain_config_tags_from_env(cfg, NULL);
	curtain_config_tags_from_env(cfg, "CURTAIN_SIMPLE_TAGS");
	curtain_config_tag_push(cfg, "_default");
	curtain_config_tag_push(cfg, "_simple_sandbox");
	curtain_config_tag_push(cfg, tag);
	r = curtain_config_apply(cfg);
	curtain_config_free(cfg);
	return (r);
}

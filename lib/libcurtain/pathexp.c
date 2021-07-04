#include <ctype.h>
#include <err.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "pathexp.h"

struct pathexp {
	char *exp_base, *exp_end;
	void *callback_data;
	int (*callback)(void *, char *);
	bool tolerate_unset_vars, tolerate_empty_vars;
	const char *error;
};

static int
error(struct pathexp *a, const char *s)
{
	a->error = s;
	return (-1);
}

static int
toobig(struct pathexp *a)
{
	return (error(a, "expanded pattern too large"));
}

static const char *
skip(const char *p)
{
	size_t balance = 0;
	while (*p) {
		switch (*p) {
		case '{':
			balance++;
			break;
		case ',':
			if (balance == 0)
				return (p);
			break;
		case '}':
			if (balance-- == 0)
				return (p);
			break;
		case '\\':
			if (!*++p)
				return (NULL);
			break;
		}
		p++;
	}
	return (NULL);
}

static int expand(struct pathexp *a, const char *pat, char *exp, size_t depth);

static int
expand_homedir(struct pathexp *a, const char *p, char *e, size_t depth)
{
	const char *q;
	const char *home;
	struct passwd *pw;
	q = p;
	while (*q) {
		if (*q == '\\') {
			q++;
			if (!*q)
				break;
		} else if (*q == '/')
			break;
		q++;
	}
	if (p == q) {
		home = getenv("HOME");
	} else {
		char name[q - p + 1], *t = name;
		while (p != q) {
			if (*p == '\\') {
				p++;
				if (p == q)
					break;
			}
			*t++ = *p++;
		}
		*t++ = '\0';
		pw = getpwnam(name);
		home = pw ? pw->pw_dir : NULL;
	}
	if (home) {
		size_t len;
		len = strlen(home);
		if ((size_t)(a->exp_end - e) < len)
			return (toobig(a));
		memcpy(e, home, len);
		e += len;
	}
	return (expand(a, q, e, depth));
}

static int
expand_envvar(struct pathexp *a, const char *p, char *e, size_t depth)
{
	const char *q;
	char *value;
	bool brace;
	if ((brace = (*p == '{')))
		p++;
	q = p;
	while (*q && (isalnum(*q) || *q == '_'))
		q++;
	if (p == q)
		return (error(a, "empty variable name"));
	{
		char name[q - p + 1];
		memcpy(name, p, q - p);
		name[q - p] = '\0';
		value = getenv(name);
	}
	p = q;
	if (brace) {
		bool set;
		if (*p == ':') {
			p++;
			set = value && *value;
		} else
			set = value;
		if (*p == '-') {
			p++;
			if (!set)
				return (expand(a, p, e, depth + 1));
		} else if (*p == '+') {
			p++;
			if (set)
				return (expand(a, p, e, depth + 1));
		} else if (p[-1] == ':')
			return (error(a, "unexpected colon"));
		p = skip(p);
		if (!p || *p++ != '}')
			return (error(a, "expected closing brace for variable"));
	}
	if (value) {
		size_t len;
		len = strlen(value);
		if (len == 0 && !a->tolerate_empty_vars)
			return (0);
		if ((size_t)(a->exp_end - e) < len)
			return (toobig(a));
		memcpy(e, value, len);
		e += len;
	} else if (!a->tolerate_unset_vars)
		return (0);
	return (expand(a, p, e, depth));
}

static int
expand(struct pathexp *a, const char *pat, char *exp, size_t depth)
{
	while (*pat) {
		switch (*pat) {
		case '{': {
			int r, m;
			pat++;
			m = 0;
			do {
				r = expand(a, pat, exp, depth + 1);
				if (r < 0)
					return (r);
				if (r > m)
					m = r;
				pat = skip(pat);
				if (!pat)
					goto unterm;
			} while (*pat++ == ',');
			return (m);
		}
		case '}':
			if (!depth--)
				return (error(a, "unexpected closing brace"));
			pat++;
			break;
		case ',':
			if (!depth)
				goto literal;
			depth--;
			do {
				pat = skip(pat);
				if (!pat)
					goto unterm;
			} while (*pat++ == ',');
			break;
		case '~':
			return (expand_homedir(a, ++pat, exp, depth));
		case '$':
			return (expand_envvar(a, ++pat, exp, depth));
		case '\\':
			if (!*++pat)
				break;
			/* FALLTHROUGH */
		default:
literal:		if (exp == a->exp_end)
				return (toobig(a));
			*exp++ = *pat++;
			break;
		}
	}
	if (depth)
unterm:		return (error(a, "unterminated brace"));
	if (exp == a->exp_end)
		return (toobig(a));
	*exp = '\0';
	return (a->callback(a->callback_data, a->exp_base));
}

int
pathexp(const char *pat, char *exp, size_t exp_size,
    const char **err, int (*callback)(void *, char *), void *callback_data)
{
	struct pathexp a = {
		.callback = callback,
		.callback_data = callback_data,
		.exp_base = exp,
		.exp_end = exp + exp_size,
	};
	int r;
	r = expand(&a, pat, exp, 0);
	if (err)
		*err = a.error;
	return (r);
}


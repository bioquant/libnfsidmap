/*
 *  libnfsidmap.c
 *
 *  nfs idmapping library, primarily for nfs4 client/server kernel idmapping
 *  and for userland nfs4 idmapping by acl libraries.
 *
 *  Copyright (c) 2004 The Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  Marius Aamodt Eriksen <marius@umich.edu>
 *  J. Bruce Fields <bfields@umich.edu>
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the University nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 *  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 *  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 *  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <netdb.h>
#include <err.h>
#include "nfsidmap.h"
#include "nfsidmap_internal.h"
#include "cfg.h"

/* forward declarations */
int set_trans_method(char *);

static char *default_domain;

#ifndef PATH_IDMAPDCONF
#define PATH_IDMAPDCONF "/etc/idmapd.conf"
#endif

static int domain_from_dns(char **domain)
{
	struct hostent *he;
	char hname[64], *c;

	if (gethostname(hname, sizeof(hname)) == -1)
		return -1;
	if ((he = gethostbyname(hname)) == NULL)
		return -1;
	if ((c = strchr(he->h_name, '.')) == NULL || *++c == '\0')
		return -1;
	*domain = strdup(c);
	return 0;
}

static struct trans_func *trans = NULL;

int nfs4_init_name_mapping(char *conffile)
{
	int ret;
	char *method;

	/* XXX: need to be able to reload configurations... */
	if (trans) /* already succesfully initialized */
		return 0;
	if (conffile)
		conf_path = conffile;
	else
		conf_path = PATH_IDMAPDCONF;
	conf_init();
	default_domain = conf_get_str("General", "Domain");
	if (default_domain == NULL) {
		ret = domain_from_dns(&default_domain);
		if (ret) {
			warnx("unable to determine a default nfsv4 domain; "
				" consider specifying one in idmapd.conf\n");
			return ret;
		}
	}
	method = conf_get_str("Translation", "Method");
	if (method == NULL)
		method = "nsswitch";
	if (set_trans_method(method) == -1) {
		warnx("Error in translation table setup");
		return -1;
	}

	if (trans->init) {
		ret = trans->init();
		if (ret) {
			trans = NULL;
			return ret;
		}
	}

	return 0;
}

char * get_default_domain(void)
{
	int ret;

	if (default_domain)
		return default_domain;
	ret = domain_from_dns(&default_domain);
	if (ret) {
		warnx("unable to determine a default nfsv4 domain; "
			" consider specifying one in idmapd.conf\n");
		default_domain = "";
	}
	return default_domain;
}

int
nfs4_get_default_domain(char *server, char *domain, size_t len)
{
	char *d = get_default_domain();

	if (strlen(d) + 1 > len)
		return -ERANGE;
	strcpy(domain, d);
	return 0;
}

extern struct trans_func nss_trans;
extern struct trans_func umichldap_trans;

#define TR_SIZE 2
static struct trans_func * t_array[TR_SIZE] = {
	[0] = &nss_trans,
	[1] = &umichldap_trans,
};

int
set_trans_method(char *method)
{
	int i;

	trans = NULL;
	for (i = 0; i < TR_SIZE; i++) {
		if (strcmp(t_array[i]->name, method) == 0) {
			trans = t_array[i];
			return 0;
		}
	}
	return -1;
}

int nfs4_uid_to_name(uid_t uid, char *domain, char *name, size_t len)
{
	int ret;

	ret = nfs4_init_name_mapping(NULL);
	if (ret)
		return ret;
	return trans->uid_to_name(uid, domain, name, len);
}

int nfs4_gid_to_name(gid_t gid, char *domain, char *name, size_t len)
{
	int ret;

	ret = nfs4_init_name_mapping(NULL);
	if (ret)
		return ret;
	return trans->gid_to_name(gid, domain, name, len);
}

int nfs4_name_to_uid(char *name, uid_t *uid)
{
	int ret;

	ret = nfs4_init_name_mapping(NULL);
	if (ret)
		return ret;
	return trans->name_to_uid(name, uid);
}

int nfs4_name_to_gid(char *name, gid_t *gid)
{
	int ret;

	ret = nfs4_init_name_mapping(NULL);
	if (ret)
		return ret;
	return trans->name_to_gid(name, gid);
}

int nfs4_gss_princ_to_ids(char *secname, char *princ, uid_t *uid, gid_t *gid)
{
	int ret;

	ret = nfs4_init_name_mapping(NULL);
	if (ret)
		return ret;
	return trans->princ_to_ids(secname, princ, uid, gid);
}

int nfs4_gss_princ_to_grouplist(char *secname, char *princ,
		gid_t *groups, int *ngroups)
{
	int ret;

	ret = nfs4_init_name_mapping(NULL);
	if (ret)
		return ret;
	return trans->gss_princ_to_grouplist(secname, princ, groups, ngroups);
}

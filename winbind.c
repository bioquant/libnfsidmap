/*
 *  winbind.c
 *
 *  winbind idmapping functions.
 *
 *  Copyright (c) 2013 BioQuant, Universitaet Heidelberg
 *  All rights reserved.
 *
 *  Christian Thiemann <christian.thiemann@bioquant.uni-heidelberg.de>
 *
 *  Adapted from nss.c
 *    Copyright (c) 2004 The Regents of the University of Michigan.
 *    J. Bruce Fields <bfields@umich.edu>
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
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include "nfsidmap.h"
#include "nfsidmap_internal.h"
#include "cfg.h"
#include <syslog.h>
#include <stdint.h>
#include <stdbool.h>
#include <wbclient.h>

static int sid_to_name(struct wbcDomainSid *sid, char *name, size_t len) {
	int err = 0, i;
	char *domain, *localname;
	struct wbcDomainInfo *di = NULL;
	if (!WBC_ERROR_IS_OK(wbcLookupSid(sid, &domain, &localname, NULL)))
		return -ENOMEM;
	if (!WBC_ERROR_IS_OK(wbcDomainInfo(domain, &di)))
		err = -ENOMEM;
	else if (strlen(localname) + strlen(di->dns_name) + 2 > len)
			err = -EAGAIN;
	else {
		strcpy(name, localname);
		strcat(name, "@");
		char *realm = name + strlen(name);
		strcat(name, di->dns_name);
		for (i = 0; i < strlen(realm); i++)
			realm[i] = toupper(realm[i]);
	}
	wbcFreeMemory(domain);
	wbcFreeMemory(localname);
	wbcFreeMemory(di);
	return err;
}

static int name_to_sid(char *name, struct wbcDomainSid *sid) {
	int err = 0;
	enum wbcSidType sidtype;
	char *sep = strchr(name, '@');
	if (sep == NULL)
		return -EINVAL;
	*sep = '\0';
	if (!WBC_ERROR_IS_OK(wbcLookupName(sep+1, name, sid, &sidtype)))
		err = -ENOENT;
	*sep = '@';
	return err;
}

static int name_to_pwd(char *name, struct passwd **pwd) {
	int err;
	struct wbcDomainSid sid;
	if ((err = name_to_sid(name, &sid)) != 0)
		return err;
	if (!WBC_ERROR_IS_OK(wbcGetpwsid(&sid, pwd)))
		return -ENOENT;
	return 0;
}

static int winbind_uid_to_name(uid_t uid, char *domain, char *name, size_t len) {
	struct wbcDomainSid sid;
	if (!WBC_ERROR_IS_OK(wbcUidToSid(uid, &sid)))
		return -ENOENT;
	return sid_to_name(&sid, name, len);
}

static int winbind_gid_to_name(gid_t gid, char *domain, char *name, size_t len) {
	struct wbcDomainSid sid;
	if (!WBC_ERROR_IS_OK(wbcGidToSid(gid, &sid)))
		return -ENOENT;
	return sid_to_name(&sid, name, len);
}

static int winbind_name_to_uid(char *name, uid_t *uid) {
	struct passwd *pwd;
	int err = name_to_pwd(name, &pwd);
	if (err != 0) return err;
	*uid = pwd->pw_uid;
	wbcFreeMemory(pwd);
	return 0;
}

static int winbind_name_to_gid(char *name, gid_t *gid) {
	struct passwd *pwd;
	int err = name_to_pwd(name, &pwd);
	if (err != 0) return err;
	*gid = pwd->pw_gid;
	wbcFreeMemory(pwd);
	return 0;
}

static int winbind_gss_princ_to_ids(char *secname, char *princ,
			uid_t *uid, uid_t *gid, extra_mapping_params **ex) {
	if (strcmp(secname, "krb5") != 0)
		return -EINVAL;
	struct passwd *pwd;
	int err = name_to_pwd(princ, &pwd);
	if (err != 0) return err;
	*uid = pwd->pw_uid;
	*gid = pwd->pw_gid;
	wbcFreeMemory(pwd);
	return 0;
}

int winbind_gss_princ_to_grouplist(char *secname, char *princ,
		       gid_t *groups, int *ngroups, extra_mapping_params **ex) {
	int err = 0, ngrps, i;
	struct wbcDomainSid sid, *grps;
	if (strcmp(secname, "krb5") != 0)
		return -EINVAL;
	if ((err = name_to_sid(princ, &sid)) != 0)
		return err;
	if (!WBC_ERROR_IS_OK(wbcLookupUserSids(&sid, true, &ngrps, &grps)))
		return -ENOENT;
	if (ngrps > *ngroups)
		err = -EAGAIN;
	else {
		for (i = 0; i < ngrps; i++)
			if (!WBC_ERROR_IS_OK(wbcSidToGid(&grps[i], &groups[i])))
				err = -ENOENT;
	}
	*ngroups = ngrps;
	if (ngrps > 0)
		wbcFreeMemory(grps);
	return err;
}


struct trans_func winbind_trans = {
	.name		= "winbind",
	.init		= NULL,
	.princ_to_ids	= winbind_gss_princ_to_ids,
	.name_to_uid	= winbind_name_to_uid,
	.name_to_gid	= winbind_name_to_gid,
	.uid_to_name	= winbind_uid_to_name,
	.gid_to_name	= winbind_gid_to_name,
	.gss_princ_to_grouplist = winbind_gss_princ_to_grouplist,
};

struct trans_func *libnfsidmap_plugin_init() {
	return (&winbind_trans);
}


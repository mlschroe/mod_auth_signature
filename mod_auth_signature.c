/*
 * mod_auth_signature - Apache module for Signature authentication
 *
 * Copyright 2022 SUSE LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "apr_lib.h"
#include "ap_config.h"
#include "apr_strings.h"
#include "apr_base64.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

#include "mod_auth.h"

#define ERRTAG "Auth_Signature: "

typedef struct {
    const char *verification_program;
    const char *ssh_allowed_signers_file;
    const char *ssh_allowed_signers_env;
    const char *armor_type;
    int no_signature_check_in_authentication;
    int allowed_clock_skew;
    int add_basic_auth;
} auth_signature_config_rec;

module AP_MODULE_DECLARE_DATA auth_signature_module;

static const command_rec auth_signature_cmds[] =
{
    AP_INIT_TAKE1("AuthSignatureVerificationProgram", ap_set_string_slot,
	(void *)APR_OFFSETOF(auth_signature_config_rec, verification_program),
	OR_AUTHCFG, "External program that is called to verify signatures"),
    AP_INIT_TAKE1("AuthSignatureSSHAllowedSignersFile", ap_set_string_slot,
	(void *)APR_OFFSETOF(auth_signature_config_rec, ssh_allowed_signers_file),
	OR_AUTHCFG, "File containing the allowed signers"),
    AP_INIT_TAKE1("AuthSignatureSSHAllowedSignersEnv", ap_set_string_slot,
	(void *)APR_OFFSETOF(auth_signature_config_rec, ssh_allowed_signers_env),
	OR_AUTHCFG, "Request environment containing the allowed ssh pubkeys"),
    AP_INIT_TAKE1("AuthSignatureAllowedClockSkew", ap_set_int_slot,
	(void *)APR_OFFSETOF(auth_signature_config_rec, allowed_clock_skew),
	OR_AUTHCFG, "Allowed difference in time"),
    AP_INIT_FLAG("AuthSignatureNoSignatureCheckInAuthentication", ap_set_flag_slot,
	(void *)APR_OFFSETOF(auth_signature_config_rec, no_signature_check_in_authentication),
	OR_AUTHCFG, "Turn off signature checking in authentication hook"),
    AP_INIT_TAKE1("AuthSignatureArmorType", ap_set_string_slot,
	(void *)APR_OFFSETOF(auth_signature_config_rec, armor_type),
	OR_AUTHCFG, "Specify the armor type to use to create signature armor"),
    AP_INIT_FLAG("AuthSignatureAddBasicAuth", ap_set_flag_slot,
	(void *)APR_OFFSETOF(auth_signature_config_rec, add_basic_auth),
	OR_AUTHCFG, "Also add a Basic auth header element"),
    {NULL}
};

static void *create_auth_signature_dir_config(apr_pool_t *p, char *d)
{
    auth_signature_config_rec *conf = apr_palloc(p, sizeof(*conf));
    conf->verification_program = NULL;
    conf->ssh_allowed_signers_file = NULL;
    conf->ssh_allowed_signers_env= NULL;
    conf->armor_type = NULL;
    conf->no_signature_check_in_authentication = 0;
    conf->allowed_clock_skew = 300;
    conf->add_basic_auth = 0;
    return conf;
}

static int note_signature_auth_failure(request_rec *r)
{
    const char *realm = ap_auth_name(r);
    const char *key = (PROXYREQ_PROXY == r->proxyreq) ? "Proxy-Authenticate" : "WWW-Authenticate";
    auth_signature_config_rec *conf = ap_get_module_config(r->per_dir_config, &auth_signature_module);
    if (!realm)
	return HTTP_INTERNAL_SERVER_ERROR;
    if (conf->add_basic_auth) {
        const char *basicauth;
        basicauth = apr_pstrcat(r->pool, "Basic realm=\"", realm, "\"", NULL);
        // adding basic auth twice due to broken client implementations which either use only first or last
	apr_table_setn(r->err_headers_out, key, basicauth);
	apr_table_addn(r->err_headers_out, key, apr_pstrcat(r->pool, "Signature realm=\"", realm, "\",headers=\"(created)\"", NULL));
	apr_table_addn(r->err_headers_out, key, basicauth);
    } else {
        const char *sigauth;
        sigauth = apr_pstrcat(r->pool, "Signature realm=\"", realm, "\",headers=\"(created)\"", NULL);
	apr_table_setn(r->err_headers_out, key, sigauth);
    }
    return HTTP_UNAUTHORIZED;
}

static void get_kv(char **linep, char **kp, char **vp)
{
    char *line = *linep;
    char *keyend, *valend;
    while (apr_isspace(*line))
    	line++;
    *kp = line;
    while (*line && *line != '=' && *line != ',' && !apr_isspace(*line))
	line++;
    keyend = line;
    while (apr_isspace(*line))
    	line++;
    *vp = valend = NULL;

    if (*line == '=') {
	line++;
	while (apr_isspace(*line))
	    line++;
	*vp = line;
	if (*line == '\"') {
	    valend = line;
	    line++;
	    while (*line && *line != '\"') {
		if (*line == '\\' && line[1])
		    line++;
	    	*valend++ = *line++;
	    }
	    if (*line)
		line++;
	} else {
	    while (*line && *line != ',' && !apr_isspace(*line))
		line++;
	    valend = line;
	}
    }
    while (*line && *line != ',')
	line++;
    while (*line == ',')
	line++;
    *keyend = 0;
    if (valend)
	*valend = 0;
    *linep = line;
}

static int get_signature_auth(request_rec *r, const char **keyid, const char **algorithm, const char **headers, const char **signature, const char **created, const char **expires)
{
    const char *auth_line;
    char *params, *k, *v;
    auth_line = apr_table_get(r->headers_in, (PROXYREQ_PROXY == r->proxyreq)
			? "Proxy-Authorization"
			: "Authorization");
    if (!auth_line)
        return HTTP_UNAUTHORIZED;
    if (strcasecmp(ap_getword(r->pool, &auth_line, ' '), "Signature"))
        return HTTP_UNAUTHORIZED;
    params = apr_pstrdup(r->pool, auth_line);
    while (*params) {
	get_kv(&params, &k, &v);
	if (!strcasecmp(k, "keyid") && v)
	    *keyid = v;
	if (!strcasecmp(k, "algorithm") && v)
	    *algorithm = v;
	if (!strcasecmp(k, "signature") && v)
	    *signature = v;
	if (!strcasecmp(k, "headers") && v)
	    *headers = v;
	if (!strcasecmp(k, "created") && v)
	    *created = v;
	if (!strcasecmp(k, "expires") && v)
	    *expires = v;
    }
    return OK;
}

static const char *write_into_tmpfile(request_rec *r, const char *tmpdir, const char *template, const char *data, int datalen)
{
    apr_file_t *f;
    char *filename = apr_psprintf(r->pool, "%s/%s", tmpdir, template);
    if (apr_file_mktemp(&f, filename, APR_FOPEN_CREATE|APR_FOPEN_WRITE|APR_FOPEN_EXCL, r->pool) != APR_SUCCESS) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, ERRTAG "apr_file_mktemp failed");
        return 0;
    }
    while (datalen > 0) {
	apr_size_t nb = datalen;
	if (apr_file_write(f, data, &nb) != APR_SUCCESS) {
	    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, ERRTAG "apr_file_write failed");
	    return 0;
	}
	data += nb;
	datalen -= nb;
    }
    if (apr_file_close(f) != APR_SUCCESS) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, ERRTAG "apr_file_close failed");
        return 0;
    }
    return filename;
}

static int run_external_verify(request_rec *r, const char *cmd, const char * const *argv)
{
    apr_pool_t *p = r->pool;
    apr_procattr_t *procattr;
    apr_proc_t *proc;
    char buffer[1024];
    apr_exit_why_e ewhy;
    int exit_code;

    if (!(proc = apr_pcalloc(p, sizeof(*proc))))
	return HTTP_INTERNAL_SERVER_ERROR;
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "running %s", cmd);
    if (   APR_SUCCESS == apr_procattr_create(&procattr, p)
        && APR_SUCCESS == apr_procattr_io_set(procattr, APR_NO_FILE,
                                                    APR_NO_PIPE, APR_FULL_BLOCK)
        && APR_SUCCESS == apr_procattr_cmdtype_set(procattr, APR_PROGRAM)
        && APR_SUCCESS == apr_proc_create(proc, cmd, argv, NULL, procattr, p)) {

	/* read stderr and log on INFO for possible fault analysis. */
	while (APR_SUCCESS == apr_file_gets(buffer, sizeof(buffer)-1, proc->err)) {
	    ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r, ERRTAG "cmd(%s) stderr: %s", cmd, buffer);
	}
	apr_file_close(proc->err);
	if (apr_proc_wait(proc, &exit_code, &ewhy, APR_WAIT) == APR_CHILD_DONE) {
	    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "command %s returned %d", cmd, exit_code);
	    return ewhy == APR_PROC_EXIT && exit_code == 0 ? OK : HTTP_UNAUTHORIZED;
	}
	return HTTP_UNAUTHORIZED;
    }
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, ERRTAG "could not run %s", cmd);
    return HTTP_UNAUTHORIZED;
}

static const char *make_allowed_signers_from_env(request_rec *r, const char *keyid, const char *envvar, const char *tempdir)
{
    char *allowedsigners = (char *)apr_table_get(r->subprocess_env, envvar);
    char *tok = NULL;
    char *line;
    const char *allowed = "";

    if (!allowedsigners)
	return NULL;
    allowedsigners = apr_pstrdup(r->pool, allowedsigners);
    while ((line = apr_strtok(allowedsigners, "\r\n", &tok)) != NULL) {
	allowedsigners = NULL;
	while (apr_isspace(*line))
	    line++;
	allowed = apr_psprintf(r->pool, "%s%s %s\n", allowed, keyid, line);
    }
    if (!*allowed)
	return NULL;
    return write_into_tmpfile(r, tempdir, "authallowed-XXXXXX", allowed, strlen(allowed));
}

static int verify_signature(request_rec *r, auth_signature_config_rec *conf, const char *keyid, const char *algorithm, const char *signdata, const char *signature, int signature_length)
{
    const char *argv[8];
    const char *tempdir;
    const char *signaturefile;
    const char *signdatafile;
    const char *allowedsigners = NULL;
    int res;

    if (!conf->verification_program) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "AuthSignatureVerificationProgram is not set");
	return HTTP_INTERNAL_SERVER_ERROR;
    }
    if (apr_temp_dir_get(&tempdir, r->pool)) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "apr_temp_dir_get failed");
	return HTTP_INTERNAL_SERVER_ERROR;
    }
    signaturefile = write_into_tmpfile(r, tempdir, "authsig-XXXXXX", signature, signature_length);
    if (!signaturefile)
	return HTTP_INTERNAL_SERVER_ERROR;
    signdatafile = write_into_tmpfile(r, tempdir, "authdata-XXXXXX", signdata, strlen(signdata));
    if (!signdatafile)
	return HTTP_INTERNAL_SERVER_ERROR;
    if (conf->ssh_allowed_signers_file)
	allowedsigners = conf->ssh_allowed_signers_file;
    else if (conf->ssh_allowed_signers_env) {
	allowedsigners = make_allowed_signers_from_env(r, keyid, conf->ssh_allowed_signers_env, tempdir);
	if (!allowedsigners)
	    return HTTP_UNAUTHORIZED;
    }
    argv[0] = conf->verification_program;
    argv[1] = ap_auth_name(r);
    argv[2] = keyid;
    argv[3] = algorithm ? algorithm : "";
    argv[4] = signaturefile;
    argv[5] = signdatafile;
    argv[6] = allowedsigners;	/* optional */
    argv[7] = NULL;
    res = run_external_verify(r, argv[0], argv);
    return res;
}


static const char *create_sign_data(request_rec *r, const char *headers, const char *created, const char *expires)
{
    if (strcmp(headers, "(created)") != 0) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "unsupported headers parameter");
	return NULL;
    }
    if (!created) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "missing created parameter");
	return NULL;
    }
    return apr_psprintf(r->pool, "(created): %s", created);
}

static char *create_ssh_armor(request_rec *r, const char *signature, int signature_len)
{
    int len;
    char *str, *p;
    if (signature_len < 6 || strncmp(signature, "SSHSIG", 6) != 0) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "not a ssh signature");
	return NULL;
    }
    len = apr_base64_encode_len(signature_len);
    str = apr_palloc(r->pool, len + len / 70);
    len = apr_base64_encode_binary(str, (const unsigned char *)signature, signature_len) - 1;
    for (p = str; len > 70; ) {
	p += 70;
	len -= 70;
	memmove(p + 1, p, len + 1);
	*p++ = '\n';
    }
    return apr_psprintf(r->pool, "-----BEGIN SSH SIGNATURE-----\n%s\n-----END SSH SIGNATURE-----\n", str);
}

static int authenticate_signature_user(request_rec *r, int isauthorization)
{
    auth_signature_config_rec *conf = ap_get_module_config(r->per_dir_config, &auth_signature_module);
    const char *current_auth;
    const char *keyid = NULL;
    const char *algorithm = NULL;
    const char *headers = NULL;
    const char *signature = NULL;
    const char *created = NULL;
    const char *expires = NULL;
    const char *signdata;
    char *signature_decoded;
    int signature_decoded_len;
    int res;

    current_auth = ap_auth_type(r);
    if (!current_auth || strcasecmp(current_auth, "Signature"))
	return DECLINED;
    if (!ap_auth_name(r)) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "need AuthName: %s", r->uri);
	return HTTP_INTERNAL_SERVER_ERROR;
    }
    r->ap_auth_type = (char*)current_auth;
    res = get_signature_auth(r, &keyid, &algorithm, &headers, &signature, &created, &expires);
    if (res)
	return res;
    if (!keyid) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "missing keyid parameter");
	return HTTP_UNAUTHORIZED;
    }
    if (r->user && strcmp(r->user, keyid) != 0) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "keyid %s does not match user %s", keyid, r->user);
	return HTTP_UNAUTHORIZED;
    }
    r->user = (char *)keyid;
    if (!signature) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "missing signature parameter");
	return HTTP_UNAUTHORIZED;
    }

    signature_decoded_len = apr_base64_decode_len(signature);
    signature_decoded = apr_palloc(r->pool, signature_decoded_len);
    signature_decoded_len = apr_base64_decode_binary((unsigned char *)signature_decoded, signature);

    if (conf->armor_type) {
	if (!strcmp(conf->armor_type, "ssh")) {
	    signature_decoded = create_ssh_armor(r, signature_decoded, signature_decoded_len);
	    if (!signature_decoded)
		return HTTP_UNAUTHORIZED;
	    signature_decoded_len = strlen(signature_decoded);
	} else {
	    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "unsupported armor type %s", conf->armor_type);
	    return HTTP_INTERNAL_SERVER_ERROR;
	}
    }

    if (created) {
        char *end = (char *)created;
	apr_int64_t cr = apr_strtoi64(created, &end, 10);
	apr_int64_t now = (apr_int64_t)time(0);
	unsigned long long allowedskew = conf->allowed_clock_skew;
	if (cr <= 0 || *end) {
	    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "bad created parameter");
	    return HTTP_UNAUTHORIZED;
	}
	if (cr < now - allowedskew) {
	    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "signature created in the past");
	    return HTTP_UNAUTHORIZED;
	}
	if (cr > now + allowedskew) {
	    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "signature created in the future");
	    return HTTP_UNAUTHORIZED;
	}
    }
    if (expires) {
        char *end = (char *)created;
	apr_int64_t ex = apr_strtoi64(expires, &end, 10);
	apr_int64_t now = (apr_int64_t)time(0);
	if (ex <= 0 || *end) {
	    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "bad expires parameter");
	    return HTTP_UNAUTHORIZED;
	}
	if (ex > now) {
	    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "signature is expired");
	    return HTTP_UNAUTHORIZED;
	}
    }
    signdata = create_sign_data(r, headers ? headers : "(created)", created, expires);
    if (!signdata)
	return HTTP_UNAUTHORIZED;
    if (!isauthorization && conf->no_signature_check_in_authentication) {
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "skipping signature verification");
	return OK;
    }
    return verify_signature(r, conf, keyid, algorithm, signdata, signature_decoded, signature_decoded_len);
}

static authz_status auth_signature_check_authorization(request_rec *r,
    const char *require_line,
    const void *parsed_require_line)
{
    int res;
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "checking valid-auth-signature authorization");
    if (!r->user)
	return AUTHZ_DENIED_NO_USER;
    res = authenticate_signature_user(r, 1);
    return res == OK ? AUTHZ_GRANTED : AUTHZ_DENIED;
}


static const authz_provider authz_valid_auth_signature_provider =
{
    &auth_signature_check_authorization,
    NULL,
};


static int hook_authenticate_signature_user(request_rec *r)
{
    int res = authenticate_signature_user(r, 0);
    if (res == HTTP_UNAUTHORIZED)
	res = note_signature_auth_failure(r);
    return res;
}

static int hook_note_signature_auth_failure(request_rec *r, const char *auth_type)
{
    if (strcasecmp(auth_type, "Signature"))
	return DECLINED;
    note_signature_auth_failure(r);
    return OK;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_check_authn(hook_authenticate_signature_user, NULL, NULL, APR_HOOK_MIDDLE, AP_AUTH_INTERNAL_PER_CONF);
    ap_hook_note_auth_failure(hook_note_signature_auth_failure, NULL, NULL, APR_HOOK_MIDDLE);
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "valid-auth-signature",
	AUTHZ_PROVIDER_VERSION, &authz_valid_auth_signature_provider, AP_AUTH_INTERNAL_PER_CONF);
}

AP_DECLARE_MODULE(auth_signature) =
{
    STANDARD20_MODULE_STUFF,
    create_auth_signature_dir_config, /* dir config creater */
    NULL,                          /* dir merger --- default is to override */
    NULL,                          /* server config */
    NULL,                          /* merge server config */
    auth_signature_cmds,           /* command apr_table_t */
    register_hooks                 /* register hooks */
};


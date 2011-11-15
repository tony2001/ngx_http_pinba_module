/*
 * Copyright (C) Antony Dovgal
 * loosely based on ngx_http_log_module by Igor Sysoev
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_flag_t       enable;
    ngx_array_t      *ignore_codes;
    ngx_connection_t *socket; 
} ngx_http_pinba_loc_conf_t;

static void *ngx_http_pinba_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_pinba_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_pinba_init(ngx_conf_t *cf);
static char *ngx_http_pinba_ignore_codes(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_pinba_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t  ngx_http_pinba_commands[] = { /* {{{ */

    { ngx_string("pinba_enable"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("pinba_ignore_codes"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE,
      ngx_http_pinba_ignore_codes,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("pinba_server"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_pinba_server,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
      ngx_null_command
};
/* }}} */

static ngx_http_module_t  ngx_http_pinba_module_ctx = { /* {{{ */
    NULL,                                  /* preconfiguration */
    ngx_http_pinba_init,                   /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_pinba_create_loc_conf,        /* create location configration */
    ngx_http_pinba_merge_loc_conf          /* merge location configration */
};
/* }}} */

ngx_module_t  ngx_http_pinba_module = { /* {{{ */
    NGX_MODULE_V1,
    &ngx_http_pinba_module_ctx,            /* module context */
    ngx_http_pinba_commands,               /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};
/* }}} */


static char *ngx_http_pinba_ignore_codes(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) /* {{{ */
{
    ngx_http_pinba_loc_conf_t *lcf = conf;
    ngx_str_t *value;
    ngx_uint_t i, *pcode;
    ngx_int_t code;

    if (lcf->ignore_codes == NULL) {
	lcf->ignore_codes = ngx_array_create(cf->pool, 4, sizeof(ngx_uint_t));
	if (lcf->ignore_codes == NULL) {
	    return NGX_CONF_ERROR;
	}
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
	code = ngx_atoi(value[i].data, value[i].len);
	if (code < 100 || code > 599) {
	    ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "invalid status code value \"%V\"", &value[i]);
	    return NGX_CONF_ERROR;
	}

	pcode = ngx_array_push(lcf->ignore_codes);
	if (pcode == NULL) {
	    return NGX_CONF_ERROR;
	}

	*pcode = (ngx_uint_t)code;
    }

    return NGX_CONF_OK;
}
/* }}} */

static char *ngx_http_pinba_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) /* {{{ */
{
    ngx_str_t *value;
    ngx_url_t u;

    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.no_resolve = 0;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
	if (u.err) {
	    ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "%s in pinba server \"%V\"", u.err, &u.url);
	}
	return NGX_CONF_ERROR;
    }

    if (u.no_port) {
	ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "no port in pinba server \"%V\"", &u.url);
	return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
/* }}} */

ngx_int_t ngx_http_pinba_handler(ngx_http_request_t *r) /* {{{ */
{
    ngx_http_pinba_loc_conf_t  *lcf;
    ngx_uint_t status, i, *pcode;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http pinba handler");

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_pinba_module);

    /* bail out right away if disabled */
    if (lcf->enable == 0) {
	return NGX_OK;
    }

    status = 0;

    if (r->err_status) {
	status = r->err_status;
    } else if (r->headers_out.status) {
	status = r->headers_out.status;
    }

    /* first check if the status is ignored */
    if (status > 0 && lcf->ignore_codes) {
	pcode = lcf->ignore_codes->elts;
	for (i = 0; i < lcf->ignore_codes->nelts; i++) {
	    if (status == pcode[i]) {
		/* this status is ignored, so just get outta here */
		return NGX_OK;
	    }
	}
    }

    /* ok, we may proceed then.. */


    return NGX_OK;
}
/* }}} */

static void *ngx_http_pinba_create_loc_conf(ngx_conf_t *cf) /* {{{ */
{
    ngx_http_pinba_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_pinba_loc_conf_t));
    if (conf == NULL) {
	return NULL;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->ignore_codes = NULL;
    conf->socket = NULL;

    return conf;
}
/* }}} */

static char *ngx_http_pinba_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) /* {{{ */
{
    ngx_http_pinba_loc_conf_t *prev = parent;
    ngx_http_pinba_loc_conf_t *conf = child;

    conf->enable = prev->enable;
    conf->ignore_codes = prev->ignore_codes;

    return NGX_CONF_OK;
}
/* }}} */

static ngx_int_t ngx_http_pinba_init(ngx_conf_t *cf) /* {{{ */
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
	return NGX_ERROR;
    }

    *h = ngx_http_pinba_handler;

    return NGX_OK;
}
/* }}} */

/*
 * vim600: sw=4 ts=4 fdm=marker
 */

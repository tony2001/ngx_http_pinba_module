/*
 * Copyright (C) Antony Dovgal
 * loosely based on ngx_http_log_module by Igor Sysoev
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "pinba.pb-c.h"

#define PINBA_STR_BUFFER_SIZE 257

ngx_str_t request_uri_name = ngx_string("pinba_request_uri");
ngx_str_t request_schema_name = ngx_string("pinba_request_schema");
ngx_int_t request_uri_key;
ngx_int_t request_schema_key;

typedef struct {
	ngx_flag_t   enable;
	ngx_array_t *ignore_codes;
	ngx_str_t    request_timer_name;
	ngx_int_t    request_timer_key;
	ngx_msec_t   max_timer;
	ngx_url_t    server;
	char        *buffer;
	size_t       buffer_size;
	size_t       buffer_used_len;
	struct {
		                    int fd;
		struct sockaddr_storage sockaddr;
		                    int sockaddr_len;
	} socket;
	char hostname[PINBA_STR_BUFFER_SIZE];
	Pinba__Request *request;
	size_t          request_size;
} ngx_http_pinba_loc_conf_t;

static void *ngx_http_pinba_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_pinba_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_pinba_init(ngx_conf_t *cf);
static char *ngx_http_pinba_ignore_codes(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_pinba_buffer_size(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_pinba_request_timer(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_pinba_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

typedef struct {
	ProtobufCBuffer base;
	ngx_str_t str;
} ngx_pinba_buf_t;

static ngx_command_t  ngx_http_pinba_commands[] = { /* {{{ */

    { ngx_string("pinba_enable"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("pinba_ignore_codes"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE,
      ngx_http_pinba_ignore_codes,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("pinba_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE,
      ngx_http_pinba_buffer_size,
      NGX_HTTP_LOC_CONF_OFFSET,
	  0,
      NULL },

    { ngx_string("pinba_request_timer"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE,
      ngx_http_pinba_request_timer,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("pinba_max_timer_value"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pinba_loc_conf_t, max_timer),
      NULL },

    { ngx_string("pinba_server"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
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


static char *ngx_http_pinba_request_timer(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) /* {{{ */
{
	ngx_http_pinba_loc_conf_t *lcf = conf;
	ngx_str_t *value;

	value = cf->args->elts;
	if (value[1].len == 0) {
		ngx_str_set(&lcf->request_timer_name, "");
		return NGX_CONF_OK;
	}
	if ((lcf->request_timer_name.data = ngx_pcalloc(cf->pool, value[1].len + 5)) == NULL)
		return NGX_CONF_ERROR;

	ngx_sprintf(lcf->request_timer_name.data, "arg_%V", &value[1]);
	lcf->request_timer_name.len = ngx_strlen(lcf->request_timer_name.data);
	lcf->request_timer_key = ngx_hash_key_lc(lcf->request_timer_name.data, lcf->request_timer_name.len);
	return NGX_CONF_OK;
}
/* }}} */

static char *ngx_http_pinba_ignore_codes(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) /* {{{ */
{
	ngx_http_pinba_loc_conf_t *lcf = conf;
	ngx_str_t *value;
	ngx_uint_t i, *pcode;
	ngx_int_t code;

	value = cf->args->elts;

	if (cf->args->nelts == 1 && ngx_strcmp(&value[1], "none") == 0) {
		lcf->ignore_codes = NULL;
		return NGX_OK;
	}

	if (lcf->ignore_codes == NULL) {
		lcf->ignore_codes = ngx_array_create(cf->pool, 4, sizeof(ngx_uint_t));
		if (lcf->ignore_codes == NULL) {
			return NGX_CONF_ERROR;
		}
	}

	for (i = 1; i < cf->args->nelts; i++) {
		char *dash;

		dash = ngx_strchr(value[i].data, '-');
		if (dash) {
			/* a range of values */
			u_char *data_copy, *dash_copy;
			int code1_len, code2_len, n;
			ngx_int_t code1, code2;

			code1_len = (dash - (char *)value[i].data);
			code2_len = value[i].len - code1_len;

			if (code1_len < 3 || code2_len < 3) {
				ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "invalid status code value \"%V\"", &value[i]);
				return NGX_CONF_ERROR;
			}

			data_copy = ngx_pstrdup(cf->pool, &value[i]);
			dash_copy = data_copy + code1_len;
			*dash_copy = '\0';
			
			code1 = ngx_atoi(data_copy, code1_len);
			if (code1 < 100 || code1 > 599) {
				ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "invalid status code value \"%V\", values must not be less than 100 or greater than 599", &value[i]);
				return NGX_CONF_ERROR;
			}
			
			code2 = ngx_atoi(dash_copy + 1, code2_len - 1);
			if (code2 < 100 || code2 > 599) {
				ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "invalid status code value \"%V\", values must not be less than 100 or greater than 599", &value[i]);
				return NGX_CONF_ERROR;
			}

			if (code1 >= code2) {
				ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "invalid status code value \"%V\", range end must be greater than range start", &value[i]);
				return NGX_CONF_ERROR;
			}

			for (n = code1; n <= code2; n++) {
				pcode = ngx_array_push(lcf->ignore_codes);
				if (pcode == NULL) {
					return NGX_CONF_ERROR;
				}
				*pcode = (ngx_uint_t)n;
			}


		} else {
			/* just a simple value */
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
	}

	return NGX_CONF_OK;
}
/* }}} */

static char *ngx_http_pinba_buffer_size(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) /* {{{ */
{
	ngx_http_pinba_loc_conf_t *lcf = conf;
	ngx_str_t *value;
	size_t size;

	value = cf->args->elts;

	size = ngx_parse_size(&value[1]);
	if (size == (size_t) NGX_ERROR) {
		ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "invalid buffer size \"%V\" (only values from 0 to 65507 are accepted)", &value[1]);
		return NGX_CONF_ERROR;
	}

	if (size > 65507) {
		ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "buffer size value \"%V\" is too big (only values from 0 to 65507 are accepted)", &value[1]);
		return NGX_CONF_ERROR;
	}

	lcf->buffer_size = size;
	return NGX_CONF_OK;
}
/* }}} */

static char *ngx_http_pinba_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) /* {{{ */
{
	ngx_str_t *value;
	ngx_url_t u;
	ngx_http_pinba_loc_conf_t *lcf = conf;
	struct addrinfo *ai_list, *ai_ptr, ai_hints;
	int fd, status;

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

	lcf->socket.fd = -1;
	lcf->server = u;

	if (lcf->server.host.len > 0 && lcf->server.host.data != NULL) {
		lcf->server.host.data[lcf->server.host.len] = '\0';
	}

	memset(&ai_hints, 0, sizeof(ai_hints));
	ai_hints.ai_flags = 0;
#ifdef AI_ADDRCONFIG
	ai_hints.ai_flags |= AI_ADDRCONFIG;
#endif
	ai_hints.ai_family = AF_UNSPEC;
	ai_hints.ai_socktype  = SOCK_DGRAM;
	ai_hints.ai_addr = NULL;
	ai_hints.ai_canonname = NULL;
	ai_hints.ai_next = NULL;

	ai_list = NULL;
	status = getaddrinfo((char *)lcf->server.host.data, (char *)lcf->server.port_text.data, &ai_hints, &ai_list);
	if (status != 0) {
		ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "pinba module: getaddrinfo(\"%V\") failed: %s", &lcf->server.url, gai_strerror(status));
		return NGX_CONF_ERROR;
	}

	fd = -1;
	for (ai_ptr = ai_list; ai_ptr != NULL; ai_ptr = ai_ptr->ai_next) {
		fd = socket(ai_ptr->ai_family, ai_ptr->ai_socktype, ai_ptr->ai_protocol);
		if (fd >= 0) {
			lcf->socket.fd = fd;
			memcpy(&lcf->socket.sockaddr, ai_ptr->ai_addr, ai_ptr->ai_addrlen);
			lcf->socket.sockaddr_len = ai_ptr->ai_addrlen;
			break;
		}
	}

	freeaddrinfo(ai_list);
	if (fd < 0) {
		ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "pinba module: socket() failed: %s", strerror(errno));
		return NGX_CONF_ERROR;
	}
	return NGX_CONF_OK;
}
/* }}} */

static int ngx_http_pinba_send_data(ngx_http_pinba_loc_conf_t *lcf, ngx_http_request_t *r, Pinba__Request *request, size_t packed_size) /* {{{ */
{
	uint8_t *buf;
	int res;

	if (packed_size == 0) {
		packed_size = pinba__request__get_packed_size(request);
	}

	buf = ngx_pcalloc(r->pool, packed_size);
	pinba__request__pack(request, buf);

	res = sendto(lcf->socket.fd, buf, packed_size, 0,
				(struct sockaddr *) &lcf->socket.sockaddr, lcf->socket.sockaddr_len);
	ngx_pfree(r->pool, buf);
	return res;
}
/* }}} */

static int ngx_http_pinba_push_into_buffer(ngx_http_pinba_loc_conf_t *lcf, ngx_http_request_t *r, Pinba__Request *request, int packed_size) /* {{{ */
{
	if (lcf->buffer_size != NGX_CONF_UNSET_SIZE  && lcf->buffer_size > 0) {
		if (lcf->request == NULL) {
			lcf->request = request;
		} else if ((lcf->request_size + packed_size) > lcf->buffer_size) {
			ngx_http_pinba_send_data(lcf, r, lcf->request, 0);
			pinba__request__free_unpacked(lcf->request, NULL);
			lcf->request = request;
		} else {
			lcf->request->requests = realloc(lcf->request->requests, sizeof(Pinba__Request *) * (lcf->request->n_requests + 1));
			if (lcf->request->requests) {
				lcf->request->requests[lcf->request->n_requests] = request;
				lcf->request->n_requests++;
				lcf->request_size += packed_size;
			}
		}
		return 0;
	}
	return -1;
}
/* }}} */

static ngx_int_t ngx_http_pinba_tag_append(ngx_http_request_t *r,
					   size_t *count,
					   uint32_t **members,
					   ngx_int_t idx) /* {{{ */
{
	uint32_t *new;
	(*count)++;
	new = realloc(*members, sizeof(*new) * (*count));
	if (new == NULL)
		return NGX_ERROR;
	new[*count - 1] = idx;
	*members = new;
	return NGX_OK;
}
/* }}} */

static ngx_int_t ngx_http_pinba_tag_add_to_dictionary(ngx_http_request_t *r,
						      Pinba__Request *request,
						      ngx_str_t *key) /* {{{ */
{
	/* Maybe the tag already exists? */
	size_t i;
	char **new;
	for (i = 0; i < request->n_dictionary; i++) {
		if (key->len != strlen(request->dictionary[i])) continue;
		if (ngx_strncmp(request->dictionary[i], key->data, key->len) == 0)
			return i;
	}
	/* No, add it */
	request->n_dictionary++;
	new = realloc(request->dictionary, sizeof(*new) * request->n_dictionary);
	if (new == NULL)
		return NGX_ERROR;
	new[request->n_dictionary - 1] = strndup(key->data, key->len);
	request->dictionary = new;
	return request->n_dictionary - 1;
}
/* }}} */

static ngx_int_t ngx_http_pinba_add_tags(ngx_http_request_t *r,
					 Pinba__Request *request) /* {{{ */
{
    ngx_http_core_main_conf_t  *cmcf;
    ngx_http_variable_value_t *v;
    ngx_http_variable_t *k;
    ngx_uint_t i, j;
    ngx_int_t ik, iv;
    ngx_str_t value, key;
    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
    k = cmcf->variables.elts;
    for (i = 0, j = 0; i < cmcf->variables.nelts; i++) {
	    if (k[i].name.len < sizeof("pinba_tag_") ||
		ngx_strncmp(k[i].name.data, "pinba_tag_", sizeof("pinba_tag_") - 1) != 0)
		    continue;
	    v = ngx_http_get_indexed_variable(r, i);
	    if (v == NULL || v->not_found || !v->valid || v->len == 0) {
		    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				   "pinba: cannot get value of tag variable %V", &k[i]);
		    continue;
	    }
	    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			   "pinba: found tag variable %V: %v", &k[i].name, v);

	    value.data = v->data; value.len = v->len;
	    key.data = k[i].name.data; key.data += sizeof("pinba_tag_") - 1;
	    key.len = k[i].name.len; key.len -= sizeof("pinba_tag_") - 1;
	    if ((ik = ngx_http_pinba_tag_add_to_dictionary(r, request,
							   &key)) == NGX_ERROR ||
		(iv = ngx_http_pinba_tag_add_to_dictionary(r, request,
							   &value)) == NGX_ERROR ||
		ngx_http_pinba_tag_append(r,
					  &request->n_timer_tag_name,
					  &request->timer_tag_name,
					  ik) == NGX_ERROR ||
		ngx_http_pinba_tag_append(r,
					  &request->n_timer_tag_value,
					  &request->timer_tag_value,
					  iv) == NGX_ERROR)
		    return NGX_ERROR;

	    j++;
    }

    if (j > 0) {
	    request->timer_tag_count = calloc(1, sizeof(*request->timer_tag_count));
	    if (request->timer_tag_count == NULL)
		    return NGX_ERROR;
	    *request->timer_tag_count = j;
	    request->n_timer_tag_count = 1;

	    /* We account one hit only */
	    request->timer_hit_count = calloc(1, sizeof(*request->timer_hit_count));
	    if (request->timer_hit_count == NULL)
		    return NGX_ERROR;
	    *request->timer_hit_count = 1;
	    request->n_timer_hit_count = 1;

	    /* We copy the timer value */
	    request->timer_value = calloc(1, sizeof(*request->timer_value));
	    if (request->timer_value == NULL)
		    return NGX_ERROR;
	    *request->timer_value = request->request_time;
	    request->n_timer_value = 1;
    }
    return NGX_OK;
}
/* }}} */

ngx_int_t ngx_http_pinba_handler(ngx_http_request_t *r) /* {{{ */
{
	ngx_http_pinba_loc_conf_t  *lcf;
	ngx_uint_t status, i, *pcode;
	ngx_http_variable_value_t *request_uri;
	ngx_http_variable_value_t *request_schema;
	ngx_http_variable_value_t *request_timer;

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

	if (lcf->socket.fd < 0) {
		/* no socket -> no data */
		return NGX_OK; /* doesn't matter, the return status is ignored anyway */
	}
	
	/* ok, we may proceed then.. */

	{
		char hostname[PINBA_STR_BUFFER_SIZE] = {0}, server_name[PINBA_STR_BUFFER_SIZE] = {0}, script_name[PINBA_STR_BUFFER_SIZE] = {0};
		ngx_time_t *tp;
		ngx_msec_int_t ms;
		size_t packed_size;
		Pinba__Request *request;
		
		request = malloc(sizeof(Pinba__Request));
		pinba__request__init(request);

		if (lcf->hostname[0] == '\0') {
			if (gethostname(hostname, sizeof(hostname)) == 0) {
				memcpy(lcf->hostname, hostname, PINBA_STR_BUFFER_SIZE);
			} else {
				memcpy(lcf->hostname, "unknown", sizeof("unknown"));
			}
		}

		/* hostname */
		request->hostname = strdup(lcf->hostname);

		memcpy(server_name, r->headers_in.server.data, (r->headers_in.server.len > PINBA_STR_BUFFER_SIZE) ? PINBA_STR_BUFFER_SIZE : r->headers_in.server.len);
		request->server_name = strdup(server_name);

		request_uri = ngx_http_get_variable(r, &request_uri_name, request_uri_key);

		if (request_uri && !request_uri->not_found && request_uri->len > 0) {
			/* try variable first */
			memcpy(script_name, request_uri->data, (request_uri->len > PINBA_STR_BUFFER_SIZE) ? PINBA_STR_BUFFER_SIZE : request_uri->len);
		} else {
			u_char *q = NULL;
			int uri_len = r->unparsed_uri.len;

			/* default script_name is $request_uri with GET parameters cut off */

			if (r->unparsed_uri.data && r->unparsed_uri.len) {
				q = (u_char *)ngx_strchr(r->unparsed_uri.data, '?');
				if (q) {
					uri_len = q - r->unparsed_uri.data;
				}

			}
			memcpy(script_name, r->unparsed_uri.data, (uri_len > PINBA_STR_BUFFER_SIZE) ? PINBA_STR_BUFFER_SIZE : uri_len);
		}
		request->script_name = strdup(script_name);

		request_schema = ngx_http_get_variable(r, &request_schema_name, request_schema_key);

		if (request_schema && !request_schema->not_found && request_schema->len) {
			request->schema = malloc(request_schema->len + 1);
			if (request->schema) {
				memcpy(request->schema, request_schema->data, request_schema->len);
				request->schema[request_schema->len] = '\0';
			}
		} else {

#if (NGX_HTTP_SSL)
			if (r->connection->ssl)
				request->schema = strdup("https");
			else
#endif
				request->schema = strdup("http");
		}

		request->document_size = r->connection->sent;

		if (lcf->request_timer_name.data && lcf->request_timer_name.len > 0) {
			/* Try to find the variable in the query */
			ngx_str_t value;
			request_timer = ngx_http_get_variable(r,
							      &lcf->request_timer_name,
							      lcf->request_timer_key);
			if (!request_timer || request_timer->not_found) {
				ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
					       "pinba: timer %V not found",
					       &lcf->request_timer_name);
				pinba__request__free_unpacked(request, NULL);
				return NGX_ERROR;
			}
			ms = ngx_atoi(request_timer->data, request_timer->len);
			if (ms == NGX_ERROR) {
				ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
					       "pinba: invalid timer value: %v",
					       request_timer);
				pinba__request__free_unpacked(request, NULL);
				return NGX_ERROR;
			}
		} else {
			tp = ngx_timeofday();
			ms = (ngx_msec_int_t) ((tp->sec - r->start_sec) * 1000 + (tp->msec - r->start_msec));
		}
		ms = (ms >= 0) ? ms : 0;
		if (lcf->max_timer != NGX_CONF_UNSET_MSEC &&
		    ms > lcf->max_timer) {
			ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				       "pinba: out of bound timer value: %M > %M",
				       ms, lcf->max_timer);
			pinba__request__free_unpacked(request, NULL);
			return NGX_ERROR;
		}
		request->request_time = (float)ms/1000;

		request->status = r->headers_out.status;
		request->has_status = 1;

		/* just nullify other fields for now */
		request->request_count = 0;
		request->memory_peak = 0;
		request->ru_utime = 0;
		request->ru_stime = 0;

		/* add tags */
		if (ngx_http_pinba_add_tags(r, request) == NGX_ERROR) {
			pinba__request__free_unpacked(request, NULL);
			return NGX_ERROR;
		}

		packed_size = pinba__request__get_packed_size(request);
		if (ngx_http_pinba_push_into_buffer(lcf, r, request, packed_size) < 0) {
			ngx_http_pinba_send_data(lcf, r, request, packed_size);
			pinba__request__free_unpacked(request, NULL);
		}
	}

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
	conf->socket.fd = -1;
	conf->buffer_size = NGX_CONF_UNSET_SIZE;
	conf->max_timer = NGX_CONF_UNSET_MSEC;

	return conf;
}
/* }}} */

static char *ngx_http_pinba_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) /* {{{ */
{
	ngx_http_pinba_loc_conf_t *prev = parent;
	ngx_http_pinba_loc_conf_t *conf = child;

	ngx_conf_merge_value(conf->enable, prev->enable, 0);
	ngx_conf_merge_value(conf->max_timer, prev->max_timer, NGX_CONF_UNSET_MSEC);

	if (conf->ignore_codes == NULL) {
		conf->ignore_codes = prev->ignore_codes;
	}

	if (conf->server.host.data == NULL && conf->server.port_text.data == NULL) {
		conf->server = prev->server;
	}

	if (conf->request_timer_name.data == NULL) {
		conf->request_timer_name = prev->request_timer_name;
		conf->request_timer_key = prev->request_timer_key;
	}

	if (conf->socket.fd == -1) {
		conf->socket = prev->socket;
	}
	
	if (conf->buffer_size == NGX_CONF_UNSET_SIZE) {
		conf->buffer_size = prev->buffer_size;
		conf->buffer_used_len = 0;
		conf->buffer = NULL;
	}

	if (conf->hostname[0] == '\0' && prev->hostname[0] != '\0') {
		memcpy(conf->hostname, prev->hostname, sizeof(prev->hostname));
	}

	return NGX_CONF_OK;
}
/* }}} */

static ngx_int_t ngx_http_pinba_init(ngx_conf_t *cf) /* {{{ */
{
	ngx_http_handler_pt *h;
	ngx_http_core_main_conf_t  *cmcf;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
	if (h == NULL) {
		return NGX_ERROR;
	}

	*h = ngx_http_pinba_handler;

	request_uri_key = ngx_hash_key_lc(request_uri_name.data, request_uri_name.len);
	request_schema_key = ngx_hash_key_lc(request_schema_name.data, request_schema_name.len);

	return NGX_OK;
}
/* }}} */

/*
 * vim600: sw=4 ts=4 fdm=marker
 */

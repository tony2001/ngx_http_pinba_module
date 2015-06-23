/*
 * Copyright (C) Antony Dovgal
 * loosely based on ngx_http_log_module by Igor Sysoev
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "uthash.h"

#include <sys/time.h>
#include <sys/resource.h>

#include "pinba.pb-c.h"

#define PINBA_STR_BUFFER_SIZE 257
#define PINBA_WORD_SIZE 256
#define PINBA_SERVER_SIZE 256
#define PINBA_PORT_SIZE 8

ngx_str_t request_uri_name = ngx_string("pinba_request_uri");
ngx_str_t request_schema_name = ngx_string("pinba_request_schema");
ngx_str_t hostname_name = ngx_string("pinba_hostname");
ngx_int_t request_uri_key;
ngx_int_t request_schema_key;
ngx_int_t hostname_key;

typedef struct {
	char name[PINBA_WORD_SIZE];
	int name_len;
	ngx_http_complex_value_t *name_cv;
	char value[PINBA_WORD_SIZE];
	int value_len;
	ngx_http_complex_value_t *value_cv;
	UT_hash_handle hh;
} ngx_pinba_tag_t;

typedef struct {
	char str[PINBA_WORD_SIZE];
	unsigned int id;
	UT_hash_handle hh;
} ngx_pinba_word_t;

typedef struct {
	int fd;
	struct sockaddr_storage sockaddr;
	int sockaddr_len;
	time_t last_resolve_time;
} ngx_pinba_socket_t;

typedef struct {
	char key[PINBA_SERVER_SIZE + PINBA_PORT_SIZE + 1];
	char server_name[PINBA_SERVER_SIZE];
	char port[PINBA_PORT_SIZE];
	ngx_pinba_socket_t sock;
	UT_hash_handle hh;
} ngx_pinba_hash_sock_t;

typedef struct {
	ngx_flag_t   enable;
	ngx_array_t *ignore_codes;
	ngx_url_t    server;
	ngx_array_t    *tags;
	ngx_array_t    *timers;
	time_t          resolve_freq; /* default 60 sec */
} ngx_http_pinba_loc_conf_t;

typedef struct {
	double        value;
	unsigned int  hit_count;
	ngx_array_t  *tags;
	unsigned int  tag_cnt;
	ngx_http_complex_value_t *value_cv;
	ngx_http_complex_value_t *hit_count_cv;
} ngx_pinba_timer_t;

typedef struct {
	struct rusage start;
} ngx_pinba_request_ctx_t;

#define TIMER_INITIALIZER { 0.0, 0, NULL, 0, NULL, NULL}

typedef struct {
	ngx_pinba_timer_t *timer;
	ngx_conf_t        *cf;
} ngx_pinba_timer_ctx_t;

ngx_pinba_hash_sock_t *g_sock_hash = NULL;
char                   g_hostname[PINBA_STR_BUFFER_SIZE];

static void *ngx_http_pinba_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_pinba_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_pinba_init(ngx_conf_t *cf);
static char *ngx_http_pinba_ignore_codes(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_pinba_tag(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_pinba_buffer_size(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_pinba_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_pinba_timer_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

typedef struct {
	ProtobufCBuffer base;
	ngx_str_t str;
} ngx_pinba_buf_t;

#ifndef timersub
# define timersub(a, b, result)                                     \
	do {                                                            \
		(result)->tv_sec = (a)->tv_sec - (b)->tv_sec;               \
		(result)->tv_usec = (a)->tv_usec - (b)->tv_usec;            \
		if ((result)->tv_usec < 0) {                                \
			--(result)->tv_sec;                                     \
			(result)->tv_usec += 1000000;                           \
		}                                                           \
	} while (0)
#endif

#define timeval_to_float(t) (float)(t).tv_sec + (float)(t).tv_usec / 1000000.0

#define memcpy_static(buf, data, data_len, result_len)	\
	do {												\
		size_t tmp_len = (data_len);					\
		if (tmp_len >= sizeof(buf)) {					\
			tmp_len = sizeof(buf) - 1;					\
		}												\
		memcpy((buf), (data), tmp_len);					\
		(buf)[tmp_len] = '\0';							\
		(result_len) = tmp_len;							\
	} while(0);

#define memcpy_static_nl(buf, data, data_len)			\
	do {												\
		size_t tmp_len = (data_len);					\
		if (tmp_len >= sizeof(buf)) {					\
			tmp_len = sizeof(buf) - 1;					\
		}												\
		memcpy((buf), (data), tmp_len);					\
		(buf)[tmp_len] = '\0';							\
	} while(0);

static ngx_command_t  ngx_http_pinba_commands[] = { /* {{{ */

    { ngx_string("pinba_enable"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("pinba_resolve_freq"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("pinba_ignore_codes"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE,
      ngx_http_pinba_ignore_codes,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("pinba_tag"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE2,
      ngx_http_pinba_tag,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("pinba_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE,
      ngx_http_pinba_buffer_size,
      NGX_HTTP_LOC_CONF_OFFSET,
	  0,
      NULL },

    { ngx_string("pinba_server"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_pinba_server,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("pinba_timer"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE12,
      ngx_http_pinba_timer_block,
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

	value = cf->args->elts;

	if (cf->args->nelts == 1 && ngx_strcmp(&value[1], "none") == 0) {
		lcf->ignore_codes = NULL;
		return NGX_OK;
	}

	if (lcf->ignore_codes == NULL) {
		lcf->ignore_codes = ngx_array_create(cf->pool, 4, sizeof(ngx_uint_t));
		if (lcf->ignore_codes == NULL) {
			ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[pinba] failed to create ignore codes array (out of mem?)");
			return NGX_CONF_ERROR;
		}
	}

	for (i = 1; i < cf->args->nelts; i++) {
		char *dash;

		dash = ngx_strchr(value[i].data, '-');
		if (dash) {
			/* a range of values */
			u_char *data_copy, *dash_copy;
			int code1_len, code2_len, n, j;
			ngx_int_t code1, code2;

			code1_len = (dash - (char *)value[i].data);
			code2_len = value[i].len - code1_len;

			if (code1_len < 3 || code2_len < 3) {
				ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[pinba] invalid status code value \"%V\"", &value[i]);
				return NGX_CONF_ERROR;
			}

			data_copy = ngx_pstrdup(cf->pool, &value[i]);
			dash_copy = data_copy + code1_len;
			*dash_copy = '\0';

			code1 = ngx_atoi(data_copy, code1_len);
			if (code1 < 100 || code1 > 599) {
				ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[pinba] invalid status code value \"%V\", values must not be less than 100 or greater than 599", &value[i]);
				return NGX_CONF_ERROR;
			}

			for (j = code2_len - 1; j > 0; j--) {
				if (dash_copy[j] == ',' || dash_copy[j] == ' ') {
					dash_copy[j] = '\0';
					code2_len--;
				}
			}

			code2 = ngx_atoi(dash_copy + 1, code2_len - 1);
			if (code2 < 100 || code2 > 599) {
				ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[pinba] invalid status code value \"%V\", values must not be less than 100 or greater than 599", &value[i]);
				return NGX_CONF_ERROR;
			}

			if (code1 >= code2) {
				ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[pinba] invalid status code value \"%V\", range end must be greater than range start", &value[i]);
				return NGX_CONF_ERROR;
			}

			for (n = code1; n <= code2; n++) {
				pcode = ngx_array_push(lcf->ignore_codes);
				if (pcode == NULL) {
					ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[pinba] failed to allocate new ignore codes array item (out of mem?)");
					return NGX_CONF_ERROR;
				}
				*pcode = (ngx_uint_t)n;
			}


		} else {
			/* just a simple value */
			code = ngx_atoi(value[i].data, value[i].len);
			if (code < 100 || code > 599) {
				ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[pinba] invalid status code value \"%V\"", &value[i]);
				return NGX_CONF_ERROR;
			}

			pcode = ngx_array_push(lcf->ignore_codes);
			if (pcode == NULL) {
				ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[pinba] failed to allocate new ignore codes array item (out of mem?)");
				return NGX_CONF_ERROR;
			}

			*pcode = (ngx_uint_t)code;
		}
	}

	return NGX_CONF_OK;
}
/* }}} */

static char *ngx_pinba_parse_tag_str(ngx_conf_t *cf, ngx_pinba_tag_t *tag, ngx_str_t *name, ngx_str_t *value) /* {{{ */
{
	ngx_http_complex_value_t cv;
	ngx_http_compile_complex_value_t ccv;

	tag->name[0] = '\0';
	tag->value[0] = '\0';

	ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
	ccv.cf = cf;
	ccv.value = name;
	ccv.complex_value = &cv;

	if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
		return NGX_CONF_ERROR;
	}

	if (cv.lengths == NULL) {
		memcpy_static(tag->name, name->data, name->len, tag->name_len);
		tag->name_cv = NULL;
	} else {
		tag->name_cv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
		if (tag->name_cv == NULL) {
			return NGX_CONF_ERROR;
		}

		*tag->name_cv = cv;
	}

	ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
	ccv.cf = cf;
	ccv.value = value;
	ccv.complex_value = &cv;

	if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
		return NGX_CONF_ERROR;
	}

	if (cv.lengths == NULL) {
		memcpy_static(tag->value, value->data, value->len, tag->value_len);
		tag->value_cv = NULL;
	} else {
		tag->value_cv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
		if (tag->value_cv == NULL) {
			return NGX_CONF_ERROR;
		}

		*tag->value_cv = cv;
	}

	return NGX_CONF_OK;
}
/* }}} */

static ngx_pinba_tag_t *ngx_pinba_prepare_tag(ngx_http_request_t *r, ngx_pinba_tag_t *tag, ngx_array_t *prepared_tags) /* {{{ */
{
	ngx_str_t v;
	ngx_pinba_tag_t *prepared_tag, tmp_tag;

	if (tag->name_cv) {
		if (ngx_http_complex_value(r, tag->name_cv, &v) != NGX_OK) {
			return NULL;
		}
		memcpy_static(tmp_tag.name, v.data, v.len, tmp_tag.name_len);
	} else {
		memcpy(tmp_tag.name, tag->name, sizeof(tag->name));
		tmp_tag.name_len = tag->name_len;
	}

	if (tag->value_cv) {
		if (ngx_http_complex_value(r, tag->value_cv, &v) != NGX_OK) {
			return NULL;
		}
		memcpy_static(tmp_tag.value, v.data, v.len, tmp_tag.value_len);
	} else {
		memcpy(tmp_tag.value, tag->value, sizeof(tag->value));
		tmp_tag.value_len = tag->value_len;
	}

	prepared_tag = ngx_array_push(prepared_tags);
	if (!prepared_tags) {
		return NULL;
	}
	*prepared_tag = tmp_tag;
	return prepared_tag;
}
/* }}} */

static ngx_pinba_timer_t *ngx_pinba_prepare_timer(ngx_http_request_t *r, ngx_pinba_timer_t *timer, ngx_array_t *prepared_timers) /* {{{ */
{
	ngx_str_t v;
	ngx_pinba_timer_t *prepared_timer, tmp_timer = TIMER_INITIALIZER;

	if (timer->value_cv) {
		char tmp_buf[32];

		if (ngx_http_complex_value(r, timer->value_cv, &v) != NGX_OK) {
			return NULL;
		}

		memcpy_static_nl(tmp_buf, v.data, v.len);

		tmp_timer.value = strtod((const char *)tmp_buf, NULL);
		if (tmp_timer.value <= 0) {
			ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "timer value must be greater than zero");
			return NULL;
		}
	}

	if (timer->hit_count_cv) {
		if (ngx_http_complex_value(r, timer->hit_count_cv, &v) != NGX_OK) {
			return NULL;
		}

		tmp_timer.hit_count = ngx_atoi(v.data, v.len);
		if (tmp_timer.hit_count <= 0) {
			ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "timer hit count must be greater than zero");
			return NULL;
		}
	}

	prepared_timer = ngx_array_push(prepared_timers);
	if (!prepared_timer) {
		return NULL;
	}
	*prepared_timer = tmp_timer;
	return prepared_timer;
}
/* }}} */

static char *ngx_http_pinba_tag(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) /* {{{ */
{
	ngx_http_pinba_loc_conf_t *lcf = conf;
	ngx_str_t *value, tag_name, tag_value;
	ngx_pinba_tag_t *tag;

	value = cf->args->elts;
	tag_name = value[1];
	tag_value = value[2];

	if (lcf->tags == NULL) {
		lcf->tags = ngx_array_create(cf->pool, 4, sizeof(ngx_pinba_tag_t));
		if (lcf->tags == NULL) {
			ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[pinba] failed to allocate request tags array (out of mem?)");
			return NGX_CONF_ERROR;
		}
	}

	tag = ngx_array_push(lcf->tags);
	if (tag == NULL) {
		ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[pinba] failed to allocate new request tags array item (out of mem?)");
		return NGX_CONF_ERROR;
	}

	if (ngx_pinba_parse_tag_str(cf, tag, &tag_name, &tag_value) != NGX_CONF_OK) {
		ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[pinba] failed to parse pinba_tag value");
		return NGX_CONF_ERROR;
	}
	return NGX_CONF_OK;
}
/* }}} */

static char *ngx_http_pinba_timer_handler(ngx_conf_t *cf, ngx_command_t *dummy, void *conf) /* {{{ */
{
	ngx_str_t         *value, tag_name, tag_value;
	ngx_pinba_timer_t *timer;
	ngx_pinba_tag_t   *tag;
	ngx_pinba_timer_ctx_t *ctx;

	ctx = cf->ctx;
	timer = ctx->timer;
	value = cf->args->elts;
	tag_name = value[0];
	tag_value = value[1];

	timer->tag_cnt++;

	tag = ngx_array_push(timer->tags);
	if (tag == NULL) {
		ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[pinba] failed to allocate new timer tags array item (out of mem?)");
		return NGX_CONF_ERROR;
	}

	if (ngx_pinba_parse_tag_str(ctx->cf, tag, &tag_name, &tag_value) != NGX_CONF_OK) {
		return NGX_CONF_ERROR;
	}
	return NGX_CONF_OK;
}
/* }}} */

static char *ngx_http_pinba_timer_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) /* {{{ */
{
	ngx_http_pinba_loc_conf_t *lcf = conf;
	char *rv;
	ngx_conf_t  save;
	ngx_str_t   *value;
	ngx_pinba_timer_t *timer;
	ngx_pinba_timer_ctx_t ctx;
	ngx_http_complex_value_t cv;
	ngx_http_compile_complex_value_t ccv;

	if (lcf->timers == NULL) {
		lcf->timers = ngx_array_create(cf->pool, 4, sizeof(ngx_pinba_timer_t));
		if (lcf->timers == NULL) {
			ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[pinba] failed to allocate timers array (out of mem?)");
			return NGX_CONF_ERROR;
		}
	}

	timer = ngx_array_push(lcf->timers);
	if (!timer) {
		ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[pinba] failed to allocate new timer (out of mem?)");
		return NGX_CONF_ERROR;
	}

	memset(timer, 0, sizeof(ngx_pinba_timer_t));

	timer->tags = ngx_array_create(cf->pool, 4, sizeof(ngx_pinba_tag_t));
	if (!timer->tags) {
		ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[pinba] failed to allocate timer tags array (out of mem?)");
		return NGX_CONF_ERROR;
	}

	timer->tag_cnt = 0;

	value = cf->args->elts;

	ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
	ccv.cf = cf;
	ccv.value = &value[1];
	ccv.complex_value = &cv;

	if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
		return NGX_CONF_ERROR;
	}

	if (cv.lengths == NULL) {
		char tmp_buf[32];

		memcpy_static_nl(tmp_buf, value[1].data, value[1].len);

		timer->value = strtod((const char *)tmp_buf, NULL);
		if (timer->value <= 0) {
			ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[pinba] timer value must be greater than zero");
			return NGX_CONF_ERROR;
		}
	} else {
		timer->value_cv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
		if (timer->value_cv == NULL) {
			return NGX_CONF_ERROR;
		}

		*timer->value_cv = cv;
	}

	if (cf->args->nelts > 2) {
		ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

		ccv.cf = cf;
		ccv.value = &value[2];
		ccv.complex_value = &cv;

		if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
			return NGX_CONF_ERROR;
		}

		if (cv.lengths == NULL) {
			timer->hit_count = ngx_atoi(value[2].data, value[2].len);
			if (timer->hit_count <= 0) {
				ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[pinba] timer hit count must be greater than zero");
				return NGX_CONF_ERROR;
			}
		} else {
			timer->hit_count_cv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
			if (timer->hit_count_cv == NULL) {
				return NGX_CONF_ERROR;
			}

			*timer->hit_count_cv = cv;
		}
	} else {
		timer->hit_count_cv = NULL;
		timer->hit_count = 1;
	}

	save = *cf;
	ctx.timer = timer;
	ctx.cf = &save;
	cf->ctx = &ctx;
	cf->handler = ngx_http_pinba_timer_handler;
	cf->handler_conf = conf;

	rv = ngx_conf_parse(cf, NULL);

	*cf = save;

	if (!timer->tags->nelts) {
		ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[pinba] timer has to have at least one timer tag");
		return NGX_CONF_ERROR;
	}

	return rv;
}
/* }}} */

static char *ngx_http_pinba_buffer_size(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) /* {{{ */
{
#if 0 /* UNUSED for now */
	ngx_http_pinba_loc_conf_t *lcf = conf;
	ngx_str_t *value;
	size_t size;

	value = cf->args->elts;

	size = ngx_parse_size(&value[1]);
	if (size == (size_t) NGX_ERROR) {
		ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[pinba] invalid buffer size \"%V\" (only values from 0 to 65507 are accepted)", &value[1]);
		return NGX_CONF_ERROR;
	}

	if (size > 65507) {
		ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[pinba] buffer size value \"%V\" is too big (only values from 0 to 65507 are accepted)", &value[1]);
		return NGX_CONF_ERROR;
	}

	lcf->buffer_size = size;
#endif
	return NGX_CONF_OK;
}
/* }}} */

static int ngx_http_pinba_resolve_and_open_socket(ngx_http_request_t *r, ngx_conf_t *cf, ngx_str_t *host, ngx_str_t *port, int resolve_freq, ngx_pinba_socket_t **sock) /* {{{ */
{
	char tmp_key[PINBA_SERVER_SIZE + PINBA_PORT_SIZE + 1];
	struct addrinfo *ai_list, *ai_ptr, ai_hints;
	int status, tmp_key_len;
	ngx_pinba_hash_sock_t *element;

	*sock = NULL;

	tmp_key_len = snprintf(tmp_key, sizeof(tmp_key), "%.*s:%.*s", (int)host->len, host->data, (int)port->len, port->data);
	if (tmp_key_len < 0) {
		if (cf) {
			ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[pinba] snprintf() failed");
		} else {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[pinba] snprintf() failed");
		}
		return -1;
	}

	HASH_FIND_STR(g_sock_hash, tmp_key, element);
	if (!element) {
		element = calloc(1, sizeof(ngx_pinba_hash_sock_t));
		if (!element) {
			if (cf) {
				ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[pinba] calloc() failed");
			} else {
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[pinba] calloc() failed");
			}
			return -1;
		}

		memcpy_static_nl(element->key, tmp_key, tmp_key_len);
		memcpy_static_nl(element->server_name, host->data, host->len);
		memcpy_static_nl(element->port, port->data, port->len);
		HASH_ADD_STR(g_sock_hash, key, element);
	} else {
		*sock = &element->sock;

		if (ngx_time() < (element->sock.last_resolve_time + resolve_freq)) {
			return (element->sock.fd < 0) ? -1 : 0;
		}

		if (element->sock.fd >= 0) {
			close(element->sock.fd);
		}
	}

	/* (re-)resolve */
	element->sock.fd = -1;

	/* reset time rightaway to prevent repeated DNS requests in case of failure */
	element->sock.last_resolve_time = ngx_time();

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
	status = getaddrinfo(element->server_name, element->port, &ai_hints, &ai_list);
	if (status != 0) {
		if (cf) {
			ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[pinba] getaddrinfo(\"%s:%s\") failed: %s", element->server_name, element->port, gai_strerror(status));
		} else {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[pinba] getaddrinfo(\"%s:%s\") failed: %s", element->server_name, element->port, gai_strerror(status));
		}
		return -1;
	}

	for (ai_ptr = ai_list; ai_ptr != NULL; ai_ptr = ai_ptr->ai_next) {
		element->sock.fd = socket(ai_ptr->ai_family, ai_ptr->ai_socktype, ai_ptr->ai_protocol);
		if (element->sock.fd >= 0) {
			memcpy(&(element->sock.sockaddr), ai_ptr->ai_addr, ai_ptr->ai_addrlen);
			element->sock.sockaddr_len = ai_ptr->ai_addrlen;
			break;
		}
	}
	freeaddrinfo(ai_list);

	if (element->sock.fd < 0) {
		if (cf) {
			ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[pinba] socket() failed: %s", strerror(status));
		} else {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[pinba] socket() failed: %s", strerror(status));
		}
		return -1;
	}

	*sock = &element->sock;
	return 0;
}
/* }}} */

static char *ngx_http_pinba_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) /* {{{ */
{
	ngx_str_t *value;
	ngx_url_t u;
	ngx_http_pinba_loc_conf_t *lcf = conf;
	int res;
	ngx_pinba_socket_t *sock;

	value = cf->args->elts;

	ngx_memzero(&u, sizeof(ngx_url_t));

	u.url = value[1];
	u.no_resolve = 1;

	if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
		if (u.err) {
			ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[pinba] %s in pinba server \"%V\"", u.err, &u.url);
		}
		return NGX_CONF_ERROR;
	}

	if (u.no_port) {
		ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[pinba] no port in pinba server \"%V\"", &u.url);
		return NGX_CONF_ERROR;
	}

	lcf->server = u;

	res = ngx_http_pinba_resolve_and_open_socket(NULL, cf, &lcf->server.host, &lcf->server.port_text, lcf->resolve_freq, &sock);
	if (res < 0) {
		return NGX_CONF_ERROR;
	}
	return NGX_CONF_OK;
}
/* }}} */

static void ngx_http_pinba_send_data(ngx_http_request_t *r, ngx_pinba_socket_t *sock, Pinba__Request *request, size_t packed_size) /* {{{ */
{
	uint8_t *buf;
	int res;

	if (packed_size == 0) {
		packed_size = pinba__request__get_packed_size(request);
	}

	buf = ngx_pcalloc(r->pool, packed_size);
	pinba__request__pack(request, buf);

	res = sendto(sock->fd, buf, packed_size, 0, (struct sockaddr *) &sock->sockaddr, sock->sockaddr_len);
	if (res < 0) {
		ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "[pinba] sendto() failed: %s", strerror(res));
	}

	ngx_pfree(r->pool, buf);
}
/* }}} */

#if 0
static int ngx_http_pinba_push_into_buffer(ngx_http_pinba_loc_conf_t *lcf, ngx_http_request_t *r, Pinba__Request *request, int packed_size) /* {{{ */
{
	if (lcf->buffer_size != NGX_CONF_UNSET_SIZE && lcf->buffer_size > 0) {
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
#endif

static inline int ngx_pinba_add_word(ngx_pinba_word_t **words, char *index_str, int index_str_len, unsigned int *word_id) /* {{{ */
{
	ngx_pinba_word_t *word;

	HASH_FIND_STR(*words, index_str, word);
	if (!word) {
		word = calloc(1, sizeof(ngx_pinba_word_t));
		if (word) {
			memcpy(word->str, index_str, index_str_len + 1);
			word->id = (*word_id)++;

			HASH_ADD_STR(*words, str, word);
			return 1;
		} else {
			return -1;
		}
	}
	return 0;
}
/* }}} */

static ngx_int_t ngx_http_pinba_handler(ngx_http_request_t *r) /* {{{ */
{
	int res;
	unsigned int word_id = 0;
	ngx_http_pinba_loc_conf_t  *lcf;
	ngx_uint_t status, i, *pcode;
	ngx_http_variable_value_t *request_uri;
	ngx_http_variable_value_t *request_schema;
	ngx_http_variable_value_t *hostname_var;
	ngx_pinba_word_t *words = NULL, *word, *word_tmp;
	ngx_pinba_request_ctx_t *ctx;
	ngx_pinba_socket_t *sock;

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http pinba handler");

	lcf = ngx_http_get_module_loc_conf(r, ngx_http_pinba_module);

	/* bail out right away if disabled */
	if (lcf->enable != 1) {
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


	res = ngx_http_pinba_resolve_and_open_socket(r, NULL, &lcf->server.host, &lcf->server.port_text, lcf->resolve_freq, &sock);
	if (res < 0) {
		return NGX_OK;
	}

	/* ok, we may proceed then.. */

	{
		char hostname[PINBA_STR_BUFFER_SIZE] = {0}, server_name[PINBA_STR_BUFFER_SIZE] = {0}, script_name[PINBA_STR_BUFFER_SIZE] = {0};
		ngx_time_t *tp;
		ngx_msec_int_t ms;
		Pinba__Request *request;

		request = malloc(sizeof(Pinba__Request));
		pinba__request__init(request);

		if (g_hostname[0] == '\0') {
			if (gethostname(hostname, sizeof(hostname)) == 0) {
				memcpy(g_hostname, hostname, PINBA_STR_BUFFER_SIZE);
			} else {
				memcpy(g_hostname, "unknown", sizeof("unknown"));
			}
		}

		/* hostname */
		hostname_var = ngx_http_get_variable(r, &hostname_name, hostname_key);

		if (hostname_var && !hostname_var->not_found && hostname_var->len) {
			request->hostname = malloc(hostname_var->len + 1);
			if (request->hostname) {
				memcpy(request->hostname, hostname_var->data, hostname_var->len);
				request->hostname[hostname_var->len] = '\0';
			}
		} else {
			request->hostname = strdup(g_hostname);
		}

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

		tp = ngx_timeofday();
		ms = (ngx_msec_int_t) ((tp->sec - r->start_sec) * 1000 + (tp->msec - r->start_msec));
		ms = (ms >= 0) ? ms : 0;
		request->request_time = (float)ms/1000;

		request->status = r->headers_out.status;
		request->has_status = 1;

		/* timers*/
		if (lcf->timers != NULL) {
			ngx_uint_t i, j;
			ngx_array_t *prepared_timers;
			ngx_pinba_timer_t *timers;
			unsigned int timer_cnt, tag_cnt;

			prepared_timers = ngx_array_create(r->pool, lcf->timers->nelts, sizeof(ngx_pinba_timer_t));
			if (prepared_timers == NULL) {
				return NGX_ERROR;
			}

			timers = lcf->timers->elts;
			timer_cnt = tag_cnt = 0;
			for (i = 0; i < lcf->timers->nelts; i++) {
				ngx_array_t *prepared_tags;
				ngx_pinba_tag_t *tags;
				ngx_pinba_timer_t *prepared_timer, *timer = &timers[i];

				prepared_tags = ngx_array_create(r->pool, timer->tags->nelts, sizeof(ngx_pinba_tag_t));
				if (prepared_tags == NULL) {
					return NGX_ERROR;
				}

				prepared_timer = ngx_pinba_prepare_timer(r, timer, prepared_timers);
				if (!prepared_timer) {
					continue;
				}

				prepared_timer->tags = prepared_tags;

				tags = timer->tags->elts;
				timer->tag_cnt = 0;

				for (j = 0; j < timer->tags->nelts; j++) {
					ngx_pinba_tag_t *prepared_tag, *tag = &tags[j];

					prepared_tag = ngx_pinba_prepare_tag(r, tag, prepared_tags);
					if (!prepared_tag) {
						continue;
					}
					ngx_pinba_add_word(&words, prepared_tag->name, prepared_tag->name_len, &word_id);
					ngx_pinba_add_word(&words, prepared_tag->value, prepared_tag->value_len, &word_id);
					prepared_timer->tag_cnt++;
				}

				if (!prepared_timer->tag_cnt) {
					continue;
				}

				tag_cnt += prepared_timer->tag_cnt;
				timer_cnt++;
			}

			request->timer_hit_count = malloc(sizeof(int) * timer_cnt);
			request->timer_value = malloc(sizeof(int) * timer_cnt);
			request->timer_tag_count = malloc(sizeof(int) * tag_cnt);
			request->timer_tag_name = malloc(sizeof(int) * tag_cnt);
			request->timer_tag_value = malloc(sizeof(int) * tag_cnt);
			request->dictionary = malloc(sizeof(char *) * word_id);

			if (request->dictionary && request->timer_hit_count && request->timer_value && request->timer_tag_count &&
				request->timer_tag_name && request->timer_tag_value) {

				timers = prepared_timers->elts;
				for (i = 0; i < prepared_timers->nelts; i++) {
					unsigned int this_tag_cnt;
					ngx_pinba_tag_t *tags;
					ngx_pinba_timer_t *timer = &timers[i];

					if (!timer->tag_cnt) {
						continue;
					}

					this_tag_cnt = 0;
					tags = timer->tags->elts;
					for (j = 0; j < timer->tags->nelts; j++) {
						ngx_pinba_tag_t *tag = &tags[j];
						unsigned int name_id;

						HASH_FIND_STR(words, tag->name, word);
						if (!word) {
							continue;
						}

						name_id = word->id;

						HASH_FIND_STR(words, tag->value, word);
						if (!word) {
							continue;
						}
						request->timer_tag_name[request->n_timer_tag_name + this_tag_cnt] = name_id;
						request->timer_tag_value[request->n_timer_tag_value + this_tag_cnt] = word->id;
						this_tag_cnt++;
					}

					if (!this_tag_cnt || timer->tag_cnt != this_tag_cnt) {
						continue;
					}

					request->timer_hit_count[request->n_timer_hit_count++] = timer->hit_count;
					request->timer_value[request->n_timer_value++] = timer->value;
					request->timer_tag_count[request->n_timer_tag_count++] = timer->tag_cnt;
					request->n_timer_tag_name += this_tag_cnt;
					request->n_timer_tag_value += this_tag_cnt;
				}
			}
		}

		/* request tags */
		if (lcf->tags != NULL) {
			ngx_uint_t i, n;
			ngx_array_t *prepared_tags;
			ngx_pinba_tag_t *tags;

			tags = lcf->tags->elts;

			prepared_tags = ngx_array_create(r->pool, lcf->tags->nelts, sizeof(ngx_pinba_tag_t));
			if (!prepared_tags) {
				return NGX_ERROR;
			}

			/* create a dictionary first (a unique string hash in fact) */
			for (i = 0; i < lcf->tags->nelts; i++) {
				ngx_pinba_tag_t *prepared_tag, *tag = &tags[i];

				prepared_tag = ngx_pinba_prepare_tag(r, tag, prepared_tags);
				if (!prepared_tag) {
					continue;
				}
				ngx_pinba_add_word(&words, prepared_tag->name, prepared_tag->name_len, &word_id);
				ngx_pinba_add_word(&words, prepared_tag->value, prepared_tag->value_len, &word_id);
			}

			n = HASH_COUNT(words);

			request->tag_name = malloc(sizeof(int) * lcf->tags->nelts);
			request->tag_value = malloc(sizeof(int) * lcf->tags->nelts);
			request->dictionary = realloc(request->dictionary, sizeof(char *) * word_id);

			if (request->tag_name && request->tag_value && request->dictionary) {
				n = 0;
				tags = prepared_tags->elts;

				/* then iterate all the strings again and use their IDs instead of values */
				for (i = 0; i < prepared_tags->nelts; i++) {
					ngx_pinba_tag_t *tag = &tags[i];

					HASH_FIND_STR(words, tag->name, word);
					if (!word) {
						continue;
					}
					request->tag_name[n] = word->id;

					HASH_FIND_STR(words, tag->value, word);
					if (!word) {
						continue;
					}
					request->tag_value[n] = word->id;
					n++;
				}
				request->n_tag_name = n;
				request->n_tag_value = n;
			}
		}

		if (lcf->timers || lcf->tags) {
			HASH_ITER(hh, words, word, word_tmp) {
				request->dictionary[word->id] = strdup(word->str);
				HASH_DEL(words, word);
				free(word);
				request->n_dictionary++;
			}
		}

		/* just nullify other fields for now */
		request->request_count = 0;
		request->memory_peak = 0;
		request->ru_utime = 0;
		request->ru_stime = 0;

		ctx = ngx_http_get_module_ctx(r, ngx_http_pinba_module);
		if (ctx) {
			struct rusage end;
			struct timeval ru_utime, ru_stime;

			if (getrusage(RUSAGE_SELF, &end) == 0) {
				timersub(&end.ru_utime, &ctx->start.ru_utime, &ru_utime);
				timersub(&end.ru_stime, &ctx->start.ru_stime, &ru_stime);
				request->ru_utime = timeval_to_float(ru_utime);
				request->ru_stime = timeval_to_float(ru_stime);
			}
		}

		ngx_http_pinba_send_data(r, sock, request, 0);
		pinba__request__free_unpacked(request, NULL);
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
	conf->tags = NULL;
	conf->timers = NULL;
	conf->resolve_freq = NGX_CONF_UNSET;

	return conf;
}
/* }}} */

static void _ngx_array_copy(ngx_pool_t *pool, ngx_array_t *src, ngx_array_t **dst) /* {{{ */
{
	*dst = ngx_array_create(pool, src->nelts, src->size);
	if (!*dst) {
		return;
	}
	memcpy((*dst)->elts, src->elts, src->nelts * src->size);
	(*dst)->nelts = src->nelts;
}
/* }}} */

static char *ngx_http_pinba_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) /* {{{ */
{
	ngx_http_pinba_loc_conf_t *prev = parent;
	ngx_http_pinba_loc_conf_t *conf = child;

	ngx_conf_merge_value(conf->enable, prev->enable, 0);

	if (prev->ignore_codes) {
		_ngx_array_copy(cf->pool, prev->ignore_codes, &conf->ignore_codes);
	}

	if (prev->tags) {
		_ngx_array_copy(cf->pool, prev->tags, &conf->tags);
	}

	if (prev->timers) {
		_ngx_array_copy(cf->pool, prev->timers, &conf->timers);
	}

	if (conf->server.host.data == NULL && conf->server.port_text.data == NULL) {
		conf->server = prev->server;
	}

	ngx_conf_merge_sec_value(conf->resolve_freq, prev->resolve_freq, 60);

	return NGX_CONF_OK;
}
/* }}} */

static ngx_int_t ngx_http_pinba_start_handler(ngx_http_request_t *r) /* {{{ */
{
	ngx_pinba_request_ctx_t *ctx;

	ctx = ngx_http_get_module_ctx(r, ngx_http_pinba_module);
	if (ctx) {
		return NGX_OK;
	}

	ctx = ngx_pcalloc(r->pool, sizeof(ngx_pinba_request_ctx_t));
	if (ctx == NULL) {
		return NGX_ERROR;
	}
	ngx_http_set_ctx(r, ctx, ngx_http_pinba_module);

	if (getrusage(RUSAGE_SELF, &ctx->start) < 0) {
		ngx_http_set_ctx(r, NULL, ngx_http_pinba_module);
	}

	return NGX_OK;
}
/* }}} */

static ngx_int_t ngx_http_pinba_init(ngx_conf_t *cf) /* {{{ */
{
	ngx_http_handler_pt *h;
	ngx_http_core_main_conf_t  *cmcf;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
	if (h == NULL) {
		return NGX_ERROR;
	}

	*h = ngx_http_pinba_start_handler;

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
	if (h == NULL) {
		return NGX_ERROR;
	}

	*h = ngx_http_pinba_handler;

	request_uri_key = ngx_hash_key_lc(request_uri_name.data, request_uri_name.len);
	request_schema_key = ngx_hash_key_lc(request_schema_name.data, request_schema_name.len);
	hostname_key = ngx_hash_key_lc(hostname_name.data, hostname_name.len);

	return NGX_OK;
}
/* }}} */

/*
 * vim600: sw=4 ts=4 fdm=marker
 */

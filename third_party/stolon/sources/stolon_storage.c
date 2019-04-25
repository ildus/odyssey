#include <string.h>
#include <jansson.h>
#include <assert.h>
#include <uuid/uuid.h>
#include <unistd.h>
#include "cetcd.h"
#include "sources/id.h"
#include "sources/pid.h"
#include "sources/list.h"
#include "sources/macro.h"
#include "sources/logger.h"
#include "sources/atomic.h"
#include "sources/config.h"
#include "sources/rules.h"
#include "sleep_lock.h"
#include "stolon_storage.h"

const int		default_sleep_interval = 3000; //5s
const int64_t	current_format_version = 1;
const char	   *clusterdata = "clusterdata";
const char	   *proxyinfodir = "proxies/info";

#define set_fast_check_interval(state) (state->check_interval = state->check_interval_fast)
#define set_default_check_interval(state) (state->check_interval = state->check_interval_default)

/* we can't include client.h since it goes with kiwi and other stuff */
od_id_t *od_client_id(void *client);
void od_client_onfree_cb_add(void *client, void (*cb)(void *, void *), void *arg);
void od_router_kill(void*, od_id_t*);

typedef enum {
	INIT,
	RUNNING,
	STOPPING,
	STOPPED
} checker_status_t;

typedef struct od_stolon_client od_stolon_client_t;
struct od_stolon_client
{
	od_id_t		client_id;
	od_list_t	link;
};

typedef struct od_stolon_state od_stolon_state_t;
struct od_stolon_state {
	mm_sleeplock_t	lock;
	od_logger_t	   *logger;
	void		   *router;

	cetcd_array		endpoints;
	cetcd_client	cli;
	char		   *clusterdatakey;
	char		   *proxyinfokey;
	char		   *proxy_uid;
	char		   *master_dbuid;

	int64_t				checker_id;
	checker_status_t	status;
	od_rule_custom_storage_t	storage;
	od_list_t			clients;

	int				check_interval;				//current
	int				check_interval_default;
	int				check_interval_fast;

	od_atomic_u64_t		storage_generation;
};

static inline void	od_stolon_check(void *arg);

//TODO: get rid of magic numbers
#define LOG_MESSAGES_COUNT (4)
const char *log_messages[LOG_MESSAGES_COUNT] = {
	"no proxy object available, closing connections to master",	//0
	"no db object available, closing connections to master",	//1
	"master db has changed, closing current connections",		//2
	"not proxying to master address since we aren't in the enabled proxies list" //3
};

static void
od_stolon_log(od_logger_t *logger, int msgid)
{
	static int last_msgid = -1;

	assert(msgid < LOG_MESSAGES_COUNT);
	if (msgid != last_msgid)
	{
		od_log(logger, "stolon", NULL, NULL, (char *) log_messages[msgid]);
		last_msgid = msgid;
	}
}

void *
od_stolon_init_state(void *router, od_logger_t *logger, od_stolon_config_t *config)
{
	uuid_t	uuid;
	int		len;
	char   *token,
		   *s = strdup(config->endpoints);

	od_stolon_state_t *state;

	state = (od_stolon_state_t *) calloc(sizeof(od_stolon_state_t), 1);

	mm_sleeplock_init(&state->lock);
	od_list_init(&state->clients);

	state->status = INIT;
	state->logger = logger;
	state->router = router;

	/* set sleep interval, by default 5s */
	state->check_interval_default = config->check_interval_default;
	if (state->check_interval_default <= 0)
		state->check_interval_default = default_sleep_interval;

	state->check_interval_fast = config->check_interval_fast;
	if (state->check_interval_fast <= 0)
		state->check_interval_fast = state->check_interval_default;

    cetcd_array_init(&state->endpoints, 1);
	while ((token = strtok(s, ",")) != NULL)
	{
		cetcd_array_append(&state->endpoints, token);
		s = NULL;
	}
	cetcd_client_init(&state->cli, &state->endpoints);
	//cetcd_rmdir(&state->cli, "/stolon/cluster/stolon-cluster/proxies", true);

	/* init key for cluster data */
	len = strlen(config->store_prefix) + strlen(config->cluster_name)
		+ strlen(clusterdata) + 4;	/* 3 slashes + \0 */
	state->clusterdatakey = (char *) malloc(len);
	snprintf(state->clusterdatakey, len, "/%s/%s/%s", config->store_prefix,
				config->cluster_name, clusterdata);

	/* uuid */
	state->proxy_uid = malloc(37);
	uuid_generate(uuid);
	uuid_unparse(uuid, state->proxy_uid);

	/* init key for proxy data */
	len = strlen(config->store_prefix) + strlen(config->cluster_name)
		+ strlen(proxyinfodir) + strlen(state->proxy_uid) + 5;	/* 4 slashes + \0 */
	state->proxyinfokey = (char *) malloc(len);
	snprintf(state->proxyinfokey, len, "/%s/%s/%s/%s", config->store_prefix,
				config->cluster_name, proxyinfodir, state->proxy_uid);

	/* start checking coroutine */
	set_fast_check_interval(state);
	state->checker_id = machine_coroutine_create(od_stolon_check, (void *) state);

	return state;
}

void
od_stolon_free_state(void *stolon_state)
{
	od_stolon_state_t	*state = (od_stolon_state_t *) stolon_state;
	mm_sleeplock_lock(&state->lock);
	state->status = STOPPING;
	mm_sleeplock_unlock(&state->lock);

	while (state->status != STOPPED)
	{
		set_fast_check_interval(state);
		machine_sleep(100);
	}

	cetcd_array_destroy(&state->endpoints);
    cetcd_client_destroy(&state->cli);
	free(state->clusterdatakey);
	free(state->proxyinfokey);
	free(state->proxy_uid);
	if (state->master_dbuid)
		free(state->master_dbuid);
	free(state);
}

static char *
get_json_string(json_t *obj, const char *key, char *def)
{
	json_t	*val = json_object_get(obj, key);
	if (val)
		return strdup(json_string_value(val));
	return def;
}

static od_stolon_cluster_data_t *
decode_json_response(od_stolon_state_t *state, char *jsonval)
{
	int				i;
	const char	   *key;
	json_t		   *value;
	json_error_t	error;
	json_t	*data = json_loads(jsonval, 0, &error);

	if (!data)
	{
		od_error(state->logger, "stolon", NULL, NULL,
		         "could not decode cetcd json: %s", error.text);
		return NULL;
	}

	od_stolon_cluster_data_t *cluster = calloc(sizeof(od_stolon_cluster_data_t), 1);
	cluster->format_version = json_integer_value(
			json_object_get(data, "formatVersion"));

	json_t *proxy_value = json_object_get(data, "proxy");
	if (!proxy_value)
		goto cleanup;

	json_t *dbs = json_object_get(data, "dbs");
	cluster->dbs_count = json_object_size(dbs);
	cluster->dbs = malloc(sizeof(od_db_t *) * cluster->dbs_count);

	i = 0;
	json_object_foreach(dbs, key, value)
	{
		json_t		   *status_value;
		od_db_t		   *db = calloc(sizeof(od_db_t), 1);

		db->uid = strdup(key);

		status_value = json_object_get(value, "status");
		db->listen_address = get_json_string(status_value, "listenAddress", NULL);
		db->port = atoi(get_json_string(status_value, "port", "0"));
		cluster->dbs[i++] = db;
	}

	if (cluster->dbs_count == 0)
		goto cleanup;

	json_t *proxy_spec_value = json_object_get(proxy_value, "spec");
	if (!proxy_spec_value)
	{
		od_error(state->logger, "stolon", NULL, NULL,
		         "no proxy spec details from stolon");
		goto error;
	}

	cluster->proxy = malloc(sizeof(cluster->proxy));
	cluster->proxy->generation = json_integer_value(
			json_object_get(proxy_value, "generation"));
	cluster->proxy->master_dbuid = get_json_string(proxy_spec_value, "masterDbUid", NULL);

	cluster->proxy->enabled = false;
	json_t *enabled_proxies = json_object_get(proxy_spec_value, "enabledProxies");
	if (enabled_proxies != NULL)
	{
		json_array_foreach(enabled_proxies, i, value)
		{
			if (strcmp(json_string_value(value), state->proxy_uid) == 0)
			{
				cluster->proxy->enabled = true;
				break;
			}
		}
	}

cleanup:
	json_decref(data);
	return cluster;
error:
	json_decref(data);
	free_od_cluster_data(cluster);
	return NULL;
}

static od_stolon_cluster_data_t *
od_stolon_get_cluster_data(void *stolon_state)
{
	od_stolon_cluster_data_t *res;
    cetcd_response *resp;

	od_stolon_state_t	*state = (od_stolon_state_t *) stolon_state;
	resp = cetcd_get(&state->cli, state->clusterdatakey);

	if (resp->err) {
		od_error(state->logger, "stolon", NULL, NULL,
		         "cetcd error %d: %s, %s", resp->err->ecode,
					resp->err->message, resp->err->cause);
		return NULL;
	}

	//cetcd_response_print(resp);
	res = decode_json_response(state, resp->node->value);
	cetcd_response_release(resp);
	return res;
}

static void
od_stolon_close_connections(od_stolon_state_t *stolon_state)
{
	od_list_t	*item;

	od_stolon_state_t	*state = (od_stolon_state_t *) stolon_state;
	set_fast_check_interval(state);
	state->storage_generation = 0;
	od_memory_barrier();
	memset(&state->storage, 0, sizeof(state->storage));

	/* close all connections we're aware of */
	od_list_foreach(&state->clients, item)
	{
		od_stolon_client_t	*sc;
		sc = od_container_of(item, od_stolon_client_t, link);
		od_router_kill(state->router, &sc->client_id);
	}

	/* cleanup master dbuid */
	if (state->master_dbuid)
	{
		free(state->master_dbuid);
		state->master_dbuid = NULL;
	}
}

static int
od_stolon_set_proxy(od_stolon_state_t *state, int64_t generation)
{
	uuid_t	uuid;
	char	buf[37];
	cetcd_response *resp;

	uuid_generate(uuid);
	uuid_unparse(uuid, buf);

	json_t *proxy_info = json_object();
	json_object_set(proxy_info, "InfoUID", json_string(buf));
	json_object_set(proxy_info, "UID", json_string(state->proxy_uid));
	json_object_set(proxy_info, "Generation", json_integer(generation));

	char *jsonval = json_dumps(proxy_info, 0);
	if (jsonval == NULL)
	{
		od_error(state->logger, "stolon", NULL, NULL,
				 "could not encode proxy info");
		return -1;
	}
	resp = cetcd_set(&state->cli, state->proxyinfokey, jsonval, 15000);
	if (resp->err) {
		od_error(state->logger, "stolon", NULL, NULL,
		         "cetcd error %d: %s, %s", resp->err->ecode,
					resp->err->message, resp->err->cause);
		return -1;
	}
	//cetcd_response_print(resp);
	cetcd_response_release(resp);

	free(jsonval);
	json_decref(proxy_info);

	return 0;
}

// on client removal, go through saved ids and cleanup
void on_client_free_cb(void *client, void *arg)
{
	od_list_t *item;
	od_stolon_state_t	*state = (od_stolon_state_t *) arg;

	od_id_t	*id = od_client_id(client);
	mm_sleeplock_lock(&state->lock);
	od_list_foreach(&state->clients, item)
	{
		od_stolon_client_t	*sc;
		sc = od_container_of(item, od_stolon_client_t, link);
		if (od_id_cmp(id, &sc->client_id))
		{
			od_list_unlink(&sc->link);
			free(sc);
		}
	}
	mm_sleeplock_unlock(&state->lock);
}

// this is basicly main function which is used to get server information
// for the client
void od_stolon_set_storage(void *client, void *stolon_state,
	od_rule_custom_storage_t *custom_storage)
{
	uint64_t	gen;
	od_stolon_state_t	*state = (od_stolon_state_t *) stolon_state;
	do
	{
		if ((gen = od_atomic_u64_of(&state->storage_generation)) == 0)
		{
			custom_storage->host[0] = '\0';
			return;
		}

		mm_sleeplock_lock(&state->lock);
		*custom_storage = state->storage;
		mm_sleeplock_unlock(&state->lock);
	}
	while (od_atomic_u64_of(&state->storage_generation) != gen);

	// add callback for removing client id on od_client_free
	od_client_onfree_cb_add(client, on_client_free_cb, stolon_state);

	// save client id in state list
	mm_sleeplock_lock(&state->lock);
	od_stolon_client_t *sc = malloc(sizeof(od_stolon_client_t));
	od_list_init(&sc->link);
	sc->client_id = *(od_client_id(client));
	od_list_append(&state->clients, &sc->link);
	mm_sleeplock_unlock(&state->lock);
}

static inline void
od_stolon_check(void *arg)
{
	od_stolon_state_t	*state = (od_stolon_state_t *) arg;
	mm_sleeplock_lock(&state->lock);
	state->status = RUNNING;
	mm_sleeplock_unlock(&state->lock);

	od_log(state->logger, "stolon", NULL, NULL, "stolon checker started: %d",
			state->checker_id);

	while (state->status == RUNNING)
	{
		od_stolon_cluster_data_t *cluster = od_stolon_get_cluster_data(arg);
		if (!cluster)
		{
			od_error(state->logger, "stolon", NULL, NULL,
					 "no clusterdata available, closing all connections");
			od_stolon_close_connections(state);
			goto wait;
		}
		if (cluster->format_version != current_format_version)
		{
			od_error(state->logger, "stolon", NULL, NULL,
					 "unsupported clusterdata format version, closing all connections");
			od_stolon_close_connections(state);
			goto wait;
		}
		if (!cluster->proxy)
		{
			od_stolon_log(state->logger, 0);
			od_stolon_close_connections(state);
			od_stolon_set_proxy(state, 0);
			goto wait;
		}

		od_db_t *db = NULL;

		if (cluster->proxy->master_dbuid)
		{
			for (int i = 0; i < cluster->dbs_count; i++)
			{
				if (strcmp(cluster->dbs[i]->uid, cluster->proxy->master_dbuid) == 0)
				{
					db = cluster->dbs[i];
					break;
				}
			}
		}

		if (db == NULL)
		{
			od_stolon_log(state->logger, 1);
			od_stolon_close_connections(state);
			od_stolon_set_proxy(state, cluster->proxy->generation);
			goto wait;
		}

		if (od_stolon_set_proxy(state, cluster->proxy->generation) != 0)
			goto wait;

		if (cluster->proxy->enabled)
		{
			set_default_check_interval(state);
			if (!state->master_dbuid ||
				strcmp(cluster->proxy->master_dbuid, state->master_dbuid) != 0)
			{
				od_stolon_log(state->logger, 2);
				od_stolon_close_connections(state);
				state->master_dbuid = strdup(cluster->proxy->master_dbuid);

				mm_sleeplock_lock(&state->lock);
				snprintf(state->storage.host, 128, "%s", db->listen_address);
				state->storage.port = db->port;
				od_atomic_u64_add(&state->storage_generation, 1);
				mm_sleeplock_unlock(&state->lock);
			}
		} else {
			od_stolon_log(state->logger, 3);
			od_stolon_close_connections(state);
		}

wait:
		free_od_cluster_data(cluster);

		if (state->status == RUNNING)
			machine_sleep(state->check_interval);
	}

	mm_sleeplock_lock(&state->lock);
	state->status = STOPPED;
	mm_sleeplock_unlock(&state->lock);
}

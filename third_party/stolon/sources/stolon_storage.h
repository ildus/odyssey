#ifndef STOLON_STORAGE_H
#define STOLON_STORAGE_H

#include "stdbool.h"

typedef struct od_db od_db_t;
typedef struct od_stolon_cluster_data od_stolon_cluster_data_t;
typedef struct od_stolon_proxy od_stolon_proxy_t;

struct od_db {
	char	   *uid;			// json:uid
	char	   *listen_address;	//json:status.listenAddress,omitempty
	int			port;			//json:status.port,omitempty, string
};

struct od_stolon_proxy
{
	int64_t		generation;				//json:generation,omitempty
	char	   *master_dbuid;			//json:spec.masterDbUid,omitempty
	bool		enabled;				//calc. from json:spec.enabledProxies,omitempty
};

struct od_stolon_cluster_data
{
	int64_t				format_version;			//json:formatVersion
	int					dbs_count;
	od_db_t			  **dbs;					//json:dbs
	od_stolon_proxy_t  *proxy;					//json:proxy
};

static inline void
free_od_cluster_data(od_stolon_cluster_data_t *cluster)
{
	if (!cluster)
		return;

	if (cluster->dbs)
	{
		for (int i = 0; i < cluster->dbs_count; i++)
		{
			od_db_t *db = cluster->dbs[i];
			if (db->listen_address)
				free(db->listen_address);
			free(db->uid);
			free(db);
		}
		free(cluster->dbs);
	}

	if (cluster->proxy)
	{
		if (cluster->proxy->master_dbuid)
			free(cluster->proxy->master_dbuid);
		free(cluster->proxy);
	}

	free(cluster);
}

extern void od_stolon_set_storage(void *client, void *stolon_state,
	od_rule_custom_storage_t *custom_storage);
extern void *od_stolon_init_state(void *router, od_logger_t *logger,
	od_stolon_config_t *config);
extern void od_stolon_free_state(void *stolon_state);

#endif

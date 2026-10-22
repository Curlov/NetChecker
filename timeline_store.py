"""Compact, indexed timeline events derived transactionally from scan evidence.

Raw observations remain the source of truth. This projection avoids decoding
whole scan documents on every page load; insert/update/delete triggers keep it
consistent with evidence, including rollbacks and retention cleanup.
"""

OBSERVATION_TYPES = "'host_discovery','tcp_port_scan','service_scan','known_tcp_port_scan'"
PORT_CHANGE_TYPES = "'PORT_OPENED','PORT_CLOSED','PORT_NOT_OPEN','PORT_ADDED','PORT_REMOVED'"


def observation_projection(where=''):
    valid = f"""o.network_id IS NOT NULL AND o.device_id IS NOT NULL
        AND o.observation_type IN ({OBSERVATION_TYPES})
        AND julianday(o.observed_at) IS NOT NULL {where}"""
    port = "CASE WHEN p.type='object' THEN p.value ELSE '{}' END"
    return f"""
        SELECT 'observation',o.id,-1,o.network_id,o.device_id,
            julianday(o.observed_at),o.observed_at,1,
            '', '', NULL,NULL,NULL,NULL,NULL
        FROM observations o WHERE {valid}
        UNION ALL
        SELECT 'observation',o.id,CAST(p.key AS INTEGER),o.network_id,o.device_id,
            julianday(o.observed_at),o.observed_at,3,
            lower(coalesce(nullif(json_extract({port},'$.protocol'),''),'tcp')),
            CAST(json_extract({port},'$.port') AS TEXT),
            replace(lower(coalesce(json_extract({port},'$.state'),'')),'-','_'),
            json_extract({port},'$.service'),json_extract({port},'$.product'),
            json_extract({port},'$.version'),
            (SELECT group_concat(CAST(value AS TEXT),' ') FROM json_each({port}))
        FROM observations o, json_each(
            CASE WHEN json_valid(o.data_json) THEN
                CASE WHEN json_type(o.data_json,'$.ports')='array'
                    THEN json_extract(o.data_json,'$.ports') ELSE '[]' END
                ELSE '[]' END
        ) p
        WHERE {valid} AND o.observation_type!='host_discovery'
            AND json_extract({port},'$.port') IS NOT NULL
    """


def change_projection(where=''):
    def endpoint(column):
        value = f"CASE WHEN json_valid({column}) THEN {column} ELSE '{{}}' END"
        return f"""CASE WHEN json_type({value},'$.port')='object'
            THEN json_extract({value},'$.port') ELSE {value} END"""
    return f"""
        WITH candidates AS (
            SELECT c.*, {endpoint('c.new_value_json')} AS new_endpoint,
                {endpoint('c.old_value_json')} AS old_endpoint
            FROM changes c WHERE c.network_id IS NOT NULL AND c.device_id IS NOT NULL
                AND julianday(c.detected_at) IS NOT NULL
                AND upper(c.change_type) IN ('DEVICE_MISSING',{PORT_CHANGE_TYPES}) {where}
        ), endpoints AS (
            SELECT *, CASE WHEN json_type(new_endpoint)='object'
                    AND json_extract(new_endpoint,'$.port') IS NOT NULL
                THEN new_endpoint ELSE old_endpoint END AS endpoint FROM candidates
        )
        SELECT 'change',id,-1,network_id,device_id,julianday(detected_at),detected_at,2,
            '', '', NULL,NULL,NULL,NULL,NULL FROM endpoints WHERE upper(change_type)='DEVICE_MISSING'
        UNION ALL
        SELECT 'change',id,0,network_id,device_id,julianday(detected_at),detected_at,4,
            lower(coalesce(nullif(json_extract(endpoint,'$.protocol'),''),'tcp')),
            CAST(json_extract(endpoint,'$.port') AS TEXT),
            CASE upper(change_type) WHEN 'PORT_OPENED' THEN 'open' WHEN 'PORT_ADDED' THEN 'open'
                WHEN 'PORT_CLOSED' THEN 'closed' ELSE 'not_open' END,
            json_extract(endpoint,'$.service'),json_extract(endpoint,'$.product'),
            json_extract(endpoint,'$.version'),
            (SELECT group_concat(CAST(value AS TEXT),' ') FROM json_each(endpoint))
        FROM endpoints WHERE upper(change_type) IN ({PORT_CHANGE_TYPES})
            AND json_type(endpoint)='object' AND json_extract(endpoint,'$.port') IS NOT NULL
    """


def migrate_timeline_events(connection):
    connection.execute("""
        CREATE TABLE IF NOT EXISTS timeline_events (
            source_kind TEXT NOT NULL, source_id INTEGER NOT NULL, port_index INTEGER NOT NULL,
            network_id INTEGER NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
            device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            at REAL NOT NULL, observed_at TEXT NOT NULL, kind INTEGER NOT NULL,
            protocol TEXT NOT NULL, port TEXT NOT NULL, state TEXT,
            service TEXT, product TEXT, version TEXT, search_text TEXT,
            PRIMARY KEY(source_kind,source_id,port_index)
        )
    """)
    for name, columns, condition in [
        ('day', 'network_id,at', ''),
        ('device', 'network_id,device_id,kind,at DESC,source_id DESC', ''),
        ('port', 'network_id,device_id,protocol,port,at DESC,kind DESC,source_id DESC,port_index DESC',
         ' WHERE kind IN (3,4)'),
        ('seen_open', 'network_id,device_id,protocol,port,at',
         " WHERE kind IN (3,4) AND (state='open' OR kind=4)"),
    ]:
        connection.execute(f'CREATE INDEX IF NOT EXISTS idx_timeline_{name} ON timeline_events({columns}){condition}')
    for table, source_kind, projection in [
        ('observations', 'observation', observation_projection),
        ('changes', 'change', change_projection),
    ]:
        connection.execute('INSERT OR IGNORE INTO timeline_events ' + projection())
        alias = 'o' if table == 'observations' else 'c'
        insert = 'INSERT INTO timeline_events ' + projection(f'AND {alias}.id=NEW.id') + ';'
        delete = f"DELETE FROM timeline_events WHERE source_kind='{source_kind}' AND source_id=OLD.id;"
        for operation, body in [('INSERT', insert), ('UPDATE', delete + insert), ('DELETE', delete)]:
            connection.execute(f"""CREATE TRIGGER IF NOT EXISTS timeline_{table}_{operation.lower()}
                AFTER {operation} ON {table} BEGIN {body} END""")

WITH
params AS (
    SELECT
        1785070139::integer AS clock_from,
        1785242939::integer AS clock_to
),

target_items AS MATERIALIZED (
    SELECT
        i.itemid,
        i.name AS item_name,
        i.value_type,
        h.hostid,
        h.name AS host_name
    FROM items i
    JOIN hosts h
      ON h.hostid = i.hostid
     AND h.status = 0
    WHERE i.status = 0
      AND i.flags != 2
      AND EXISTS (
          SELECT 1
          FROM item_tag it
          WHERE it.itemid = i.itemid
            AND it.tag = 'Application'
            AND it.value = 'cert-date'
      )
),

host_tags AS MATERIALIZED (
    SELECT
        ht.hostid,

        string_agg(DISTINCT ht.value, ', ' ORDER BY ht.value)
            FILTER (WHERE ht.tag = 'ENV') AS env,

        string_agg(DISTINCT ht.value, ', ' ORDER BY ht.value)
            FILTER (WHERE ht.tag = 'GAS') AS gas,

        string_agg(DISTINCT ht.value, ', ' ORDER BY ht.value)
            FILTER (WHERE ht.tag = 'AS') AS as_tag

    FROM host_tag ht
    WHERE ht.tag IN ('ENV', 'GAS', 'AS')
      AND EXISTS (
          SELECT 1
          FROM target_items ti
          WHERE ti.hostid = ht.hostid
      )
    GROUP BY ht.hostid
)

SELECT
    ti.host_name AS "Объект мониторинга",
    ti.item_name AS "Метрика",
    lh.value     AS "Дней осталось",
    ht.env       AS "ENV",
    ht.gas       AS "ГАС",
    ht.as_tag    AS "АС"
FROM target_items ti
CROSS JOIN params p

LEFT JOIN LATERAL (
    (
        SELECT h.value::text AS value
        FROM history h
        WHERE ti.value_type = 0
          AND h.itemid = ti.itemid
          AND h.clock BETWEEN p.clock_from AND p.clock_to
        ORDER BY h.clock DESC
        LIMIT 1
    )

    UNION ALL

    (
        SELECT h.value::text
        FROM history_str h
        WHERE ti.value_type = 1
          AND h.itemid = ti.itemid
          AND h.clock BETWEEN p.clock_from AND p.clock_to
        ORDER BY h.clock DESC
        LIMIT 1
    )

    UNION ALL

    (
        SELECT h.value::text
        FROM history_log h
        WHERE ti.value_type = 2
          AND h.itemid = ti.itemid
          AND h.clock BETWEEN p.clock_from AND p.clock_to
        ORDER BY h.clock DESC
        LIMIT 1
    )

    UNION ALL

    (
        SELECT h.value::text
        FROM history_uint h
        WHERE ti.value_type = 3
          AND h.itemid = ti.itemid
          AND h.clock BETWEEN p.clock_from AND p.clock_to
        ORDER BY h.clock DESC
        LIMIT 1
    )

    UNION ALL

    (
        SELECT h.value::text
        FROM history_text h
        WHERE ti.value_type = 4
          AND h.itemid = ti.itemid
          AND h.clock BETWEEN p.clock_from AND p.clock_to
        ORDER BY h.clock DESC
        LIMIT 1
    )
) lh ON true

LEFT JOIN host_tags ht
  ON ht.hostid = ti.hostid

ORDER BY
    ti.host_name,
    ti.item_name;


CREATE INDEX CONCURRENTLY item_tag_tag_value_itemid_idx
    ON item_tag (tag, value, itemid);

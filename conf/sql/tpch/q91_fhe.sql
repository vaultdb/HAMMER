SELECT l_returnflag, l_linestatus, COUNT(*)::BIGINT as count_order
FROM lineitem
WHERE l_shipdate <= date '1998-08-03'
GROUP BY l_returnflag, l_linestatus
ORDER BY l_returnflag, l_linestatus

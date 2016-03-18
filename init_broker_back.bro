# This policy should be loaded on to the cluster node
#  which is responsable for being the broker back
#  end server.
#
# To load, modify the etc/node.cfg so by adding the "aux_scripts"
#  directive.  For example:
#
# [broker]
# type=worker
# host=sigma-n
# aux_scripts="host_core/init_broker_back.bro"
#
@load host_core/broker_store_back.bro
redef USER_HIST_BACK::BROKER_ACTUAL = T;

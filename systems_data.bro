#  systems_data.bro  Scott Campbell 11/30/13
#

@load auditd_policy/util

module SYSTEMS_DATA;

export {

	type listener_data: record {
		init_id: string &default="NULL";	# who opened the listener
		command: string &default="NULL";	# what opened the listener, prob syscall name
		l_type: string &default="NULL";		# what sort of listener has been opened?
		bind_addr: string &default="NULL";	# where is it listening
		start: time;				# when did it happen?
		}

	# An individual system can have any number of associated attributes
	#  Since there is such a range of these options, we start simple then
	#  build out later if needed.
	type server: record {
		name: string &default="NULL" &log;
		listeners: table[port] of listener_data &log;



	}
	
  


event new_listener(i: Info, skt: AUDITD_POLICY::IPPD )
{
	# This event handles the creation of a new network listener on
	#  a given host.  Quite handy to keep track of these things IMHO...
	
	local t_server: server;
	local t_l_d: listener_data;

	t_l_d$init_id = i$idv[v_auid]; # who?: use immutable audit id
	t_l_d$command = i$syscall;	# what?
	t_l_d$l_type = i$s_type;
	t_l_d$bind_addr = i$s_type;
	t_l_d$time = i$ts;

	t_server$name = i$node;
	

}



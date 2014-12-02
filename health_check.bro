# 10/29/2014 Scott Campbell
#
@load isshd_policy
@load SyslogReader
 
module HOST_HEALTH;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts: time &log;
		sshd_rps: count &log &default=0;		# isshd records/sec
		sshd_s_log: count &log &default=0;	# SSHD_CORE::s_logging table holding data relevant to logging info
		sshd_s_rec: count &log &default=0;	# SSHD_CORE::s_records this is a table holding all the known server instances
       					# When a subsystem is instantiated, the process loses the cid data which is an
                			#  issue in tracking the behavior.  This table keeps track of the cid as a function
                        		#  of the ppid and sid - it will be set when the forking settles down post privsep.
		sshd_c_lkp: count &log &default=0;	#SSHD_CORE::cid_lookup 
		syslog_rps: count &log &default=0;		# syslog records/sec
		};

	global measure_interval = 1 min &redef;
}

event measure()
{
	local sshd_rps = SSHD_IN_STREAM::input_count_delta;
	local sshd_s_log = |SSHD_CORE::s_logging|;
	local sshd_s_rec = |SSHD_CORE::s_records|;
	local sshd_c_lkp = |SSHD_CORE::cid_lookup|;

	local syslog_rps = SYSLOG_PARSE::input_count_delta;

	local t_Info: Info;
	t_Info$sshd_rps = sshd_rps;
	t_Info$sshd_s_log = sshd_s_log;
	t_Info$sshd_s_rec = sshd_s_rec;
	t_Info$sshd_c_lkp = sshd_c_lkp;
	t_Info$ts = network_time();
	t_Info$syslog_rps = syslog_rps;

	Log::write(LOG, t_Info);

	schedule measure_interval { measure() };
}

event bro_init() &priority=5
{
        Log::create_stream(HOST_HEALTH::LOG, [$columns=Info]);

	# start rate monitoring for event stream
	if ( SSHD_IN_STREAM::DATANODE )
		schedule measure_interval { measure() };
}

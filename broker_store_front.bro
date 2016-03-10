# Scott Campbell, March 2016
# Implementation of broker front end as an interface for looking at 
#  historical user data and new addresses, countries and AS's.
# 
# This works in conjunction with the broker_store_back.bro as this is
#  the front end of the pair.  The data itself is stored in the back end
#  as sqlite3 db data.
#

@load base/frameworks/broker

module USER_HIST_FRONT;

export {

	redef enum Notice::Type += {
		User_NewAS,	# Generic new AS
		User_NewASOdd,	# New AS for somone who normally should not
		User_NewCountry,# New country.	
		User_NewAgent,	# Generic new user agent
		};

	# This is used for dealing with the front end of the 
	#   BrokerStore.
	global h: opaque of BrokerStore::Handle;

	# These are for the table copying routines
	type bro_set: set[string];
	type bro_table: table[string] of count;
	type bro_vector: vector of string;

	type uid_login: record {
		orig_host: table[string] of count;
		orig_as: table[string] of count;
		orig_cc: set[string];
		orig_agent: set[string];
		login_count: count &default=0;
		last_seen: time &default=double_to_time(0.00);
		};

	# This is the table that represents the "local" version of
	#  the data set.  Keep in sync with the back end.
	global uid_cache: table[string] of uid_login;

	#
	global broker_type = BrokerStore::SQLITE &redef; # storage backend to use
	global broker_name = "TestStore" &redef; #  name for the data store
	global broker_options: BrokerStore::BackendOptions; #  box-o-options
	global broker_storedb: string = "/tmp/store.sqlite" &redef;

	global broker_port: port = 9999/tcp &redef;
	global broker_host: string = "127.0.0.1" &redef;
	global broker_refresh_interval: interval = 1sec &redef;

	# Main interface for the historical data
	global process_login: function(uid: string, a: string, agent: string);


	} # end of export



function init_login_record() : uid_login
	{
	local r: uid_login;
	local oh:table[string] of count;
	local oas:table[string] of count;
	local occ:set[string];
	local oag:set[string];

	r$orig_host = oh;
	r$orig_as = oas;
	r$orig_cc = occ;
	r$orig_agent = oag;
	r$login_count = 1;
	r$last_seen = network_time();

	return r;

	}

function comm_table_to_bro_table_recurse(it: opaque of BrokerComm::TableIterator,
                                rval: bro_table): bro_table
	{
	if ( BrokerComm::table_iterator_last(it) )
		return rval;

	local item = BrokerComm::table_iterator_value(it);
	rval[BrokerComm::refine_to_string(item$key)] = BrokerComm::refine_to_count(item$val);
	BrokerComm::table_iterator_next(it);
	return comm_table_to_bro_table_recurse(it, rval);
	}

function comm_table_to_bro_table(d: BrokerComm::Data): bro_table
	{
	return comm_table_to_bro_table_recurse(BrokerComm::table_iterator(d),
	                                       bro_table());
	}

function comm_set_to_bro_set_recurse(it: opaque of BrokerComm::SetIterator,
                            rval: bro_set): bro_set
	{
	if ( BrokerComm::set_iterator_last(it) )
		return rval;

	add rval[BrokerComm::refine_to_string(BrokerComm::set_iterator_value(it))];
	BrokerComm::set_iterator_next(it);
	return comm_set_to_bro_set_recurse(it, rval);
	}


function comm_set_to_bro_set(d: BrokerComm::Data): bro_set
	{
	return comm_set_to_bro_set_recurse(BrokerComm::set_iterator(d), bro_set());
	}

function refresh_cache(uid: string)
	{
	# Because it is far simpler to interact with a native bro table 
	#  object, this function checks to see if the uid is available in
	#  the uid_cache table and if not, will set up the appropriate entries
	#  in prep for the analysis which should happen in O(~5sec).  
	#
	# If changes are introduced, write the diffs back to the broker
	#  back object.
	# 
	# type uid_login: record {
	#	orig_host: table[string] of count &default=table();
	#	orig_as: table[string] of count &default=table();
	#	orig_cc: set[string] &default=set();
	#	orig_agent: set[string] &default=set();
	#	login_count: count &default=0;
	#	last_seen: time &default=double_to_time(0.00);
	#	};
	#
	#
	local comm_uid =  BrokerComm::data(uid);

	# if uid is in local table, just scoop it up and bail
	if ( uid in uid_cache )
		{
		#print fmt("CACHE lookup HIT for %s", uid); 
		return;
		}

	# Otherwise we will need something to put in the uid_cache	
	local r: uid_login = init_login_record();

	# Go to the data store gather it up and 
	#  put in local table.  If not in data store, gen new
	#  record and put in both store and table.
	#
	when ( local res = BrokerStore::lookup(h, comm_uid) )
		{
		if ( res$result?$d )
			{
			# Record is in place so look up values and return 
			#  them unmodified
			# print fmt("lookup successful: %s %s", uid, res);
			local il: BrokerComm::Data;
		
			il = BrokerComm::record_lookup( res$result, 0);
			r$orig_host = comm_table_to_bro_table(il);
			il = BrokerComm::record_lookup( res$result, 1);
			r$orig_as = comm_table_to_bro_table(il);
			il = BrokerComm::record_lookup( res$result, 2);
			r$orig_cc = comm_set_to_bro_set(il);
			il = BrokerComm::record_lookup( res$result, 3);
			r$orig_agent =  comm_set_to_bro_set(il);
			il = BrokerComm::record_lookup( res$result, 4);
			r$login_count =  BrokerComm::refine_to_count(il);
			il = BrokerComm::record_lookup( res$result, 5);
 			r$last_seen =  BrokerComm::refine_to_time(il);

			uid_cache[uid] = r;
			}
		else {
			# The uid was not found so add it to the store
			# print fmt("lookup UNsuccessful: %s", uid);
			local comm_rec = BrokerComm::data(r);
			uid_cache[uid] = r;
			BrokerStore::insert(h, comm_uid, comm_rec);
			}

		return;

		}
	timeout 5sec
		{ print "timeout in refresh cache"; return; }

	return;
	}

event login_transaction(uid: string, a: string, agent: string)
	{
	# For the time being the agent string is not implemented. 
	#  Replace with literal value when things settle down.
	#
	local _a = to_addr(a);

	local asn = lookup_asn(_a);
	local t_as = fmt("%s", asn);
	t_as = ( |t_as| > 0 ) ? t_as : "UNKNOWN";

	local t_geo: geo_location = lookup_location(_a);
	local t_cc = ( t_geo?$country_code ) ? t_geo$country_code : "UNKNOWN";

	# For some reason the call to process_login did not do what it was 
	#  supposed to so start over.  Add a feature here to stop the 
	#  madness after a number of loops...
	if ( uid !in uid_cache ) 
		{
		#print fmt("LOGIN_TRANSACTION CACHE SKIP for %s", uid);
		schedule 5sec { login_transaction(uid,a,agent) };
		return;
		}

	local r: uid_login = uid_cache[uid];

	# Update address information
	if ( a !in r$orig_host ) {
		r$orig_host[a] = 1;
		}
	else {
		++r$orig_host[a];
		}

	# Update AS information
	if ( t_as !in r$orig_as ) {
		r$orig_as[t_as] = 1;

		# fill in some hopefully useful values
		local t_region = ( t_geo?$region ) ? t_geo$region : "UNKNOWN";
		local t_city = ( t_geo?$city ) ? t_geo$city : "UNKNOWN";

		NOTICE([$note=User_NewAS, 
			$msg=fmt("user: %s AS: AS%s CITY: %s  REGION: %s", 
				uid, t_as, t_city, t_region)]);
		}
	else {
		++r$orig_as[t_as];
		}

	# Update Country information
	# Data is a set for now
	if ( t_cc !in r$orig_cc ) {

		# fill in some hopefully useful values
		local t_cregion = ( t_geo?$region ) ? t_geo$region : "UNKNOWN";
		local t_ccity = ( t_geo?$city ) ? t_geo$city : "UNKNOWN";

		# gen list of current countries
		local t_val = "";
		for (x in r$orig_cc) {
			t_val = fmt("%s %s", t_val, x);
			}

		NOTICE([$note=User_NewCountry, 
			$msg=fmt("user: %s CC: AS%s CITY: %s  REGION: %s PREV_CC: %s", 
				uid, t_cc, t_ccity, t_cregion, t_val)]);

		add r$orig_cc[t_cc];
		}

	# Update user agent information
	if ( agent !in r$orig_agent ) {

		NOTICE([$note=User_NewAgent, 
			$msg=fmt("user: %s Agent: %s", uid, agent)]);

		add r$orig_agent[agent];
		}

	++r$login_count;
	r$last_seen = current_time();

	local t_r = BrokerComm::data(r);
	local comm_uid =  BrokerComm::data(uid);

	# sync cache
	uid_cache[uid] = r;

	# and push back to the store
	when ( local retn = BrokerStore::insert(h, comm_uid, t_r) )
		{
		#print fmt("BrokerStore::insert: %s", retn);
		}
	timeout 2sec
		{ print "timeout in log transaction"; }

	}

function process_login(uid: string, a: string, agent: string)
	{
	# This function does the work of record keeping and getting
	#  the transaction processed.  login_transaction() has no
	#  buisness being called without the cache check.
	#
	# First queue up the records for the uid
	refresh_cache(uid);
	schedule 5sec { login_transaction(uid,a,agent) };
	}

event bro_init()
	{
	BrokerComm::enable();
	BrokerComm::connect(broker_host, broker_port, broker_refresh_interval);

        # Set location of the physical sqlite file
	broker_options$sqlite$path = "/home/bro/db/login_store_f.sqlite";

	h = BrokerStore::create_frontend("BName");
	
	}


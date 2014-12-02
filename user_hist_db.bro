
module SQLITE;	

export {
	redef enum Notice::Type += {
		User_NewSubnet,
		User_NewSubnetOdd,
		User_NewCountry,
		};


	global subnet_mask = 24 &redef; 	# how fine do we chop up address space?
	global login_threshold = 10 &redef; 	# this sets the point where we start looking at history

	# Notes on db setup:
	#
	# create table login_data(
	# ts integer,
	# orig_h text,
	# resp_h text,
	# uid text,
	# auth_type text
	# );
	#
	# create table user_data(
	# uid text,
	# country_count integer,
	# net_count integer
	# );

	global user_data_db = "/home/scottc/development/SSHD_BRO/database/user_data.db" &redef;
	global w_user_data_db = "/home/scottc/development/SSHD_BRO/database/w_user_data.db" &redef;

	# this is for taking back data from the immediate query
	# data here is raw
	#
	type Val: record {
		uid: string;
		orig_h: string;
		auth_type: string;
		};

	# for the cooked data we need a more complete structure
	type userStruct: record {
		subnet_list: table[subnet] of count;
		country_list: table[string] of count;
		last_seen: time;
		total_logins: count &default=0;
		};

	# finally a place to put everything...
	global u_obj_box: table[subnet] of count;
	global uid_lookup: table[string] of userStruct;

	# for writing out new database records, we need a logging structure
	type Log: record {
		ts: int &log;
		orig_h: string &log;
		resp_h: string &log;
		uid: string &log;
		auth_type: string &log;
		};	
	redef enum Log::ID += { LOG };

	global auth_wayback_transaction: function(ts: time, id: conn_id, uid: string, svc_name: string, svc_type: string, svc_resp: string, svc_auth: string, data: string);
	
	} #end export

function open_writer() : count
{
	return 0;
}

function close_writer() : count
{
	Log::remove_filter(Log::WRITER_SQLITE, "sqltest_name");	
	return 0;
} 
	
function login_history_test(uid: string, orig_h: string) : count
{
	local t_userStruct: userStruct;
	local ret_val = 0;
	local t_sub: subnet;
	local t_geo: geo_location;

	# since this gets called after the table is filled out for the uid
	#   this should never be a problem, right?
	if ( uid in uid_lookup )
		t_userStruct = uid_lookup[uid];
	else
		return 1;		

	if ( t_userStruct$total_logins <= login_threshold ) {
		++t_userStruct$total_logins;
		uid_lookup[uid] = t_userStruct;
		return ret_val;
		}

	# *finally* we get to do something ...
	t_sub = mask_addr(to_addr(orig_h), subnet_mask);
	t_geo = lookup_location(to_addr(orig_h));

	++t_userStruct$total_logins;	

	if ( t_sub in t_userStruct$subnet_list ) {
		# nothing new!
		++t_userStruct$subnet_list[t_sub];
		#print fmt("login_history_test: nothing new %s %s %s", uid, t_sub, orig_h);
		}
	else {
		#print fmt("login_history_test: new subnet %s %s %s", uid, t_sub, orig_h);
		# new! - set local variables for clarity
		local num_subnets = |t_userStruct$subnet_list|;
		local num_logins = t_userStruct$total_logins;

		# idea here is to approximate stability with stability being ~
		#   small subnet count and large total_logins
		if ( num_subnets > 10 ) {
			NOTICE([$note=User_NewSubnet,
				$msg=fmt("New subnet %s: %s", uid, t_sub)]);
			}
		else {
			# we make this distinction since for a small number of subnets
			#  it seems more interesting when a new one is added ...
			local ts1 = "";
			#for (x in t_userStruct$subnet_list) {
			#	ts1 = fmt("%s %s", ts1, x);
			#	}

			NOTICE([$note=User_NewSubnetOdd,
				$msg=fmt("New subnet %s: %s", uid, t_sub)]);
			}

		# add the subnet to the users set
		t_userStruct$subnet_list[t_sub] = 1;
		# add record to the database


		} # end subnet check

	if ( t_geo$country_code in t_userStruct$country_list ) {
		++t_userStruct$country_list[t_geo$country_code];
		#print fmt("login_history_test country: seen country %s %s %s", uid, t_geo$country_code, orig_h);
		}
	else {
		# new country!
		# print fmt("login_history_test country: new country %s %s %s", uid, t_geo$country_code, orig_h);
		t_userStruct$country_list[t_geo$country_code] = 1;

		local tc = "";
		for (x in t_userStruct$country_list) {
			tc = fmt("%s %s", tc, x);
			#tc = fmt("%s %s", tc, x$country_code);
			}

		NOTICE([$note=User_NewCountry,
			$msg = fmt("%s: %s [%s]", uid, t_geo$country_code, tc)]);

		}

	uid_lookup[uid] = t_userStruct;	
	return ret_val;
}

# This is called for every line returned in the database query
#   returned data is: count(*),orig_h,uid,auth_type
#
# NOTE: this is not for checking the login, but creating the history for
#   acting on that login..
#
event line2(description: Input::EventDescription, tpe: Input::Event, r: Val)
{
	#print fmt("line2: %s %s", r$uid, r$orig_h);
	local t_userStruct: userStruct;
	local t_sublist: table[subnet] of count;
	local t_clist: table[string] of count;
	local t_sub: subnet;
	local t_geo: geo_location;

	local uid = r$uid;
	local orig_h = r$orig_h;

	# check and see if uid is in the local cached copy
	if ( uid !in uid_lookup ) { 
		# need a new entry - create the template
		t_userStruct$subnet_list = t_sublist;
		t_userStruct$country_list = t_clist;
		t_userStruct$last_seen = network_time();
	
		uid_lookup[uid] = t_userStruct;
		}
	else
		t_userStruct = uid_lookup[uid];	

	# create the subnet and country
	t_sub = mask_addr(to_addr(orig_h), subnet_mask);
	# lookup_location(addr) returns a type geo_location:
	# type geo_location: record {
        #	country_code: string &optional; ##< The country code.
        #	region: string &optional;       ##< The region.
        #	city: string &optional; ##< The city.
        #	latitude: double &optional;     ##< Latitude.
        #	longitude: double &optional;    ##< Longitude.
	# 	} &log;
	t_geo = lookup_location(to_addr(orig_h));

	if ( t_sub in t_userStruct$subnet_list ) {
		# this is a subnet we have seen, increment it's counter
		++t_userStruct$subnet_list[t_sub];
		}
	else {
		t_userStruct$subnet_list[t_sub] = 1;
		}

	if ( t_geo$country_code in t_userStruct$country_list ) {
		++t_userStruct$country_list[t_geo$country_code];
		}
	else {
		t_userStruct$country_list[t_geo$country_code] = 1;
		}

	++t_userStruct$total_logins;
	
	# now fill in the new entry
	uid_lookup[uid] = t_userStruct;
}

event insert_login_rec(its: int, t_orig_h: string, t_resp_h:string, uid:string, t_svc_auth:string)
	{
	# since the database is living on the management node, we need to use a simple test
	#  to avoid untold pain and suffering...
	#
	if ( Cluster::local_node_type() == Cluster::MANAGER ) {
		# print fmt("open writer ...");
		open_writer();
		# print fmt("Insert login %s %s %s @ %s -> %s", its, t_svc_auth, uid, t_orig_h, t_resp_h);
		Log::write(SQLITE::LOG, [ $ts=its, $orig_h=t_orig_h, $resp_h=t_resp_h, $uid=uid, $auth_type=t_svc_auth ]);
		# print fmt("close writer ...");
		close_writer();
		}

	}

function auth_wayback_transaction(ts: time, id: conn_id, uid: string, svc_name: string, svc_type: string, svc_resp: string, svc_auth: string, data: string)
{
	# first normalize all the non-case sensitive informaiton
	local t_svc_name = to_upper(svc_name);
	local t_svc_type = to_upper(svc_type);
	local t_svc_resp = to_upper(svc_resp);
	local t_svc_auth = to_upper(svc_auth);

	# print fmt("INSQL AUTH_TRANSACTION %s %s", t_svc_name, t_svc_resp);
 	# only interested in SSH activity
	if ( t_svc_name == "ISSHD" && t_svc_resp == "ACCEPTED" ) {
	# print("INSQL AUTH_TRANSACTION SSH ACCEPTED");

		if ( uid !in uid_lookup ) {
			
			# the uid has not been cached in the local table
			# we fix that here
	# print fmt("AUTH_TRANSACTION SSH ACCEPTED NEW UID %s", uid);
			Input::add_event(
				[
				$source=user_data_db,
				$name="userdb",
				$fields=Val,
				# will get called for each of the data points
				$ev=line2,
				$want_record=T,
				$config=table(
					["query"] = fmt("select count(*),orig_h,uid,auth_type from login_data where uid='%s' group by orig_h;", uid)
					),
				$reader=Input::READER_SQLITE
				]);
			}

		# Now that we know the uid_lookup table is populated, run
		#   the login test against it
		local orig_h_s = fmt("%s", id$orig_h);
		login_history_test(uid,orig_h_s);

		#local its: int = to_int( fmt("%s", ts));
		#local t_orig_h: string = fmt("%s", id$orig_h);
		#local t_resp_h: string = fmt("%s", id$resp_h);
		
		#event insert_login_rec(its, t_orig_h, t_resp_h, uid, t_svc_auth);
 
		} # end t_svc_name && t_svc_resp check

}

event Input::end_of_data(name: string, source:string)
    {
    if ( source == user_data_db ) {
	#print fmt("removing Input::end_of_data : name: %s source: %s compare: %s", name, source, user_data_db);
        Input::remove(name);
	}
    }

event bro_init()
	{
#	local filter: Log::Filter =
#		[
#		$name="userdb",
#		$path=w_user_data_db,
#		$config=table(["tablename"] = "login_data"),
#		$writer=Log::WRITER_SQLITE,
#		$columns=SQLITE::Log
#		];
#
#        #Log::create_stream(SQLITE::LOG, [$columns=Log]);
#        Log::create_stream(Conn::LOG, filter);
#        #Log::remove_filter(SQLITE::LOG, "default");
#
#	local config_strings: table[string] of string = {
#		["dbname"] = "login_data"
#		};
#
#        local filter: Log::Filter = [$name="sqltest_name", $path="/home/scottc/development/SSHD_BRO/database/user_data.db", $writer=Log::WRITER_SQLITE, $config=config_strings];
#        Log::create_stream(SQLITE::LOG, filter);
	}

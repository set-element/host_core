# Scott Campbell, March 2016
# Implementation of broker back end as an interface for looking at
#  historical user data and new addresses, countries and AS's.
#
# This implements the actual sqlite database and can (and prob should)
#  be run in a separate bro instance.  Besides same host/port info as the
#  front end, the broker_name also needs to be the same.
#

@load base/frameworks/broker

module USER_HIST_BACK;

export {
	global h: opaque of BrokerStore::Handle;

	type uid_login: record {
		orig_host: table[string] of count;
		orig_as: table[string] of count;
		orig_cc: set[string];
		orig_agent: set[string];
		login_count: count &default=0;
		last_seen: time &default=double_to_time(0.00);
		};

	# Current notion of the back end
	global broker_type = BrokerStore::SQLITE &redef;            # storage backend to use
	global broker_name = "TestStore" &redef;                    # name for the data store
	global broker_options: BrokerStore::BackendOptions &redef;  # box-o-options
	global broker_storedb: string = "/tmp/store.sqlite" &redef; # file to hold all the things

	global broker_port: port = 9999/tcp &redef;
	global broker_host: string = "127.0.0.1" &redef;
	global broker_refresh_interval: interval = 1sec &redef;
	}


event db_size()
	{

	when ( local ret = BrokerStore::size(h) )
		{
		print fmt("DB Size: %s", ret);
		schedule 30sec { db_size() };
		}
	timeout 5sec
		{ 
		print fmt("db_size timeout"); 
		schedule 30sec { db_size() }; 
		}
	}

function db_size_wrap()
	{
	schedule 30sec { db_size() };
	}

event bro_init()
	{
	broker_options$sqlite$path = broker_storedb;
	BrokerComm::enable();
	BrokerComm::listen(broker_port, broker_host);

	h = BrokerStore::create_master(broker_name,broker_type, broker_options );

	db_size_wrap();	
	}


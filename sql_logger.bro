# sql_logger.bro  Scott Campbell Oct 1, 2013
#
# This is a prototype implemenntation of the sqlite logger - for now it
#  is just something to demonstrate the functionality.
#
# The database needs to be created before hand with the record type being
#  identical as the Log record type.
#
# Quite a bit that can be done with this ...

@load base/protocols/conn

redef LogSQLite::unset_field = "(unset)";

module SQLITE;

export {
	global db_loaded = 1;
        redef enum Log::ID += { LOG };

        type Log: record {
                sub: subnet;
		uid: string;
		data_source: string;
		} &log;

	redef exit_only_after_terminate = T;
	redef Input::accept_unsupported_types = T;

	global auth_logger: event(_uid: string, _sub: subnet, _data_source: string);

	}

event auth_logger(u: string, s: subnet, ds: string)
	{
	# since the database is living on the management node, we need to use a simple test 
	#  to avoid untold pain and suffering...
	#
	if ( Cluster::local_node_type() == Cluster::MANAGER ) {
		Log::write(SQLITE::LOG, [ $sub=s, $uid=u, $data_source=ds ]);
		}
	}

event bro_init()
{
	# This will initialize a database at the $path location with table name $name. 
	# Will open to append in the event that data already exists there.
	# 
	#print fmt("Initializing sql logger ...");

        Log::create_stream(SQLITE::LOG, [$columns=Log]);
        Log::remove_filter(SQLITE::LOG, "default");
	
	local config_strings: table[string] of string = {
		#["dbname"] = "port",
		["dbname"] = "auth_data"
		};

        local filter: Log::Filter = [$name="sqltest_name", $path="/home/scottc/development/SSHD_BRO/database/auth", $writer=Log::WRITER_SQLITE, $config=config_strings];
        Log::add_filter(SQLITE::LOG, filter);
}

	

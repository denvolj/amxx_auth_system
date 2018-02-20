
// Структуры =================================== 
enum _:SQLD
{
	Handle:sqld_tuple,
	Handle:sqld_instance
}
// Константы ===================================
// Внутренние стандарты
const SQL_QLIM = 1024
const SQL_HLIM = 128
const VL_MAXLENGTH 	= 512
const FD_MAXLENGTH	= 128

new g_host[256] = "localhost", g_user[256] = "zombielite", g_pass[256] = "#NNEP:ZL:mysql.password();", g_database[256] = "zombielite";

// Стоки =======================================
message_table_init(plugin_name[]) {
	server_print("[%s] Database init...", plugin_name);
}

mysql_connect(host[], username[], password[], database[]) {
	new instance[SQLD];
	new s_Error[512], i_Error;
	instance[sqld_tuple] = SQL_MakeDbTuple(host, username, password, database);
	instance[sqld_instance] = SQL_Connect(instance[sqld_tuple], i_Error, s_Error, charsmax(s_Error));
	
	if(instance[sqld_instance] == Empty_Handle) {
		log_amx("[MySQL] Database connection failed. [ErrNo: %d] %s ", i_Error, s_Error);

		return instance;
	}

	return instance;
}

Handle:mysql_exec(const sql_query[], instance[SQLD]) {
	new Handle:result = SQL_PrepareQuery(instance[sqld_instance], sql_query);
	new s_Error[512];
	
	if(instance[sqld_instance] != Empty_Handle) {
		if(!SQL_Execute (result)) {
			SQL_QueryError(result, s_Error, charsmax(s_Error));
			server_print("[MySQL] SQL error: %s", s_Error);
		}
	}
	
	return result;
}

mysql_close(instance[SQLD]) {
	SQL_FreeHandle(instance[sqld_tuple]); 
	SQL_FreeHandle(instance[sqld_instance]);
}

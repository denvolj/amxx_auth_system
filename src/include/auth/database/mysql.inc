

#if defined _authorization_database_interface_included
        #endinput
#endif
#define _authorization_database_interface_included

#include <auth_core>

/*=============================== Структуры базы данных ====================================*/
enum _:SQLD
{
	Handle:sqld_tuple,
	Handle:sqld_instance
};


/*============================= Блок констант и запросов ===================================*/
const SQL_QLIM = 1024;

new const __AUTH_CREATE[] = 
        "CREATE TABLE IF NOT EXISTS auth_system\
        (\
                uid INT UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,\
                nick VARCHAR(%d) DEFAULT NULL,\
                steam VARCHAR(%d) DEFAULT NULL,\
                ip VARCHAR(%d) DEFAULT NULL,\
                pass VARCHAR(%d) DEFAULT NULL,\
                auth_fail INT(3) UNSIGNED DEFAULT 0,\
                auth_flags INT(10) UNSIGNED DEFAULT 0,\
                flags INT(10) UNSIGNED DEFAULT 0\
        ) ENGINE = InnoDB DEFAULT CHARSET=utf8;";


new const __AUTH_INSERT[] = \
        "INSERT INTO auth_system (nick, steam, ip, pass, auth_fail, auth_flags, flags)\
        VALUES(%s);";



new const __AUTH_SELECT[] =  "SELECT * FROM auth_system WHERE %s;";
new const __AUTH_UPDATE[] =  "UPDATE auth_system SET %s WHERE uid=%d;";
new const __AUTH_DELETE[] =  "DELETE FROM auth_system WHERE uid=%d;";

/*=============================== Реализация взаимодействий ================================*/
database_init() {
        new query[SQL_QLIM]; 
        format(query, SQL_QLIM-1, __AUTH_CREATE, NICK_LENGTH, STEAM_LENGTH, IP_LENGTH, CACHE_LENGTH);
        
        return mysql_exec(query, true);
}

database_create_user(data[UserStruct], threaded = true, callback[] = "mysql_query_handler", extras[] = "", size = 0) {
        new query[SQL_QLIM]; query = __AUTH_INSERT;            // Базовая строка запроса
        new temp[UserStruct];
        new values[SQL_QLIM/2];
        
        screen_object(data, temp);
        
        if(auth_equal(data, us_nickname)) 
                format(values, SQL_QLIM/2-1, "%s%s, ", values, "default");
        else 
                format(values, SQL_QLIM/2-1, "%s%s, ", values, temp[us_nickname]);
        
        if(auth_equal(data, us_steam)) 
                format(values, SQL_QLIM/2-1, "%s%s, ", values, "default");
        else 
                format(values, SQL_QLIM/2-1, "%s%s, ", values, temp[us_steam]);
                
        if(auth_equal(data, us_ip)) 
                format(values, SQL_QLIM/2-1, "%s%s, ", values, "default");
        else 
                format(values, SQL_QLIM/2-1, "%s%s, ", values, temp[us_ip]);
                
        if(auth_equal(data, us_password)) 
                format(values, SQL_QLIM/2-1, "%s%s, ", values, "default");
        else 
                format(values, SQL_QLIM/2-1, "%s%s, ", values, temp[us_password]);
                
        if(auth_equal(data, us_authfail)) 
                format(values, SQL_QLIM/2-1, "%s%s, ", values, "default");
        else 
                format(values, SQL_QLIM/2-1, "%s%d, ", values, temp[us_authfail]);
                
        if(auth_equal(data, us_authflags)) 
                format(values, SQL_QLIM/2-1, "%s%s, ", values, "default");
        else 
                format(values, SQL_QLIM/2-1, "%s%d, ", values, temp[us_authflags]);
        
        if(auth_equal(data, us_accessflags)) 
                format(values, SQL_QLIM/2-1, "%s%s", values, "default");
        else 
                format(values, SQL_QLIM/2-1, "%s%d", values, temp[us_accessflags]);
       
        format(query, SQL_QLIM-1, query, values);
        
        return mysql_exec(query, threaded, callback, extras, size);
}

database_find_user(data[UserStruct], threaded = false, callback[] = "mysql_query_handler", extras[] = "", size = 0) {
        new query[SQL_QLIM]; query = __AUTH_SELECT;
        new where_clause[SQL_QLIM/2];
        
        where_state(data, where_clause, " AND ");
        
        format(query, SQL_QLIM-1, query, where_clause);
        
        if(threaded)
                return mysql_exec(query, threaded, callback, extras, size);
        
        new Handle:result = mysql_exec(query, threaded, callback, extras, size);
        
        if(SQL_MoreResults(result)) {
		parse_results(result, data);
		return true;
	} 
	
        return false;
}

database_modify_user(user_id, data[UserStruct], threaded = true, callback[] = "mysql_query_handler", extras[] = "", size = 0) {
        new query[SQL_QLIM]; query = __AUTH_UPDATE;
        new where_clause[SQL_QLIM/2];
        
        where_state(data, where_clause, ", ");
        
        format(query, SQL_QLIM-1, query, where_clause, user_id);
        
        return mysql_exec(query, threaded, callback, extras, size);
}

database_delete_user(user_id, threaded = true, callback[] = "mysql_query_handler", extras[] = "", size = 0) {
        new query[SQL_QLIM]; query = __AUTH_DELETE;
        
        format(query, SQL_QLIM-1, query, user_id);
        
        return mysql_exec(query, threaded, callback, extras, size);
}

/*==================================== Стоковые функции ====================================*/
stock mysql_singletone(host[] = "localhost", username[] = "root", password[] = "root", database[] = "zombielite") {
        static instance[SQLD];
        if(instance[sqld_instance] == Empty_Handle) {
                mysql_close(instance);
                instance = mysql_connect(host, username, password, database);
        }
        
        return instance;
}

stock mysql_connect(host[], username[], password[], database[]) {
        new instance[SQLD];
        new s_Error[SQL_QLIM/2], i_Error;
        instance[sqld_tuple] = _:SQL_MakeDbTuple(host, username, password, database);
        instance[sqld_instance] = _:SQL_Connect(instance[sqld_tuple], i_Error, s_Error, charsmax(s_Error));

        if(instance[sqld_instance] == Empty_Handle) {
                log_amx("[MySQL] Database connection failed. [ErrNo: %d] %s ", i_Error, s_Error);

                return instance;
        }

        return instance;
}

stock any:mysql_exec(const sql_query[], new_thread = false, callback[] = "mysql_query_handler", extras[] = "", size = 0) {
        new s_Error[SQL_QLIM/2];
        static instance[SQLD];
        
        if(instance[sqld_instance] == Empty_Handle || instance[sqld_tuple] == Empty_Handle)
        instance = mysql_singletone();
        
        if(new_thread) {
                SQL_ThreadQuery(instance[sqld_tuple], callback, sql_query, extras, size);
        }
        else {
                        
                new Handle:result = SQL_PrepareQuery(instance[sqld_instance], sql_query);
                
                if(!SQL_Execute (result)) {
                        SQL_QueryError(result, s_Error, charsmax(s_Error));
                        server_print("[MySQL] SQL error: %s", s_Error);
                }
                return result;
        }

        return true;
}

public mysql_query_handler(failstate, Handle:query, error[], errnum, data[], size, Float:queuetime) {
        if(failstate != TQUERY_SUCCESS)    server_print("[MySQL] SQL error [%d]: %s", errnum, error);
}

public database_identify(failstate, Handle:query, error[], errnum, data[], size, Float:queuetime) {
        new user[UserStruct] = user_proto_default;
        if(SQL_MoreResults(query)) {
		parse_results(query, user);
	} 
        server_print("[AuthSystem] Calling back");
	identify_client(data[0], user, data[1]);
}

stock mysql_close(instance[SQLD]) {
        if(instance[sqld_tuple] != Empty_Handle)
                SQL_FreeHandle(instance[sqld_tuple]); 
        
        if(instance[sqld_instance] != Empty_Handle)
                SQL_FreeHandle(instance[sqld_instance]);
}

stock mysql_escape_string(dest[], len, const source[])
{
	copy(dest, len, source);
	
	replace_all(dest,len,"\\","\\\\");
	replace_all(dest,len,"\0","\\0'");
	replace_all(dest,len,"\n","\\n");
	replace_all(dest,len,"\r","\\r");
	replace_all(dest,len,"'","\'");
	replace_all(dest,len,"`","\`");
	replace_all(dest,len,"\x1a","\\x1a");
	replace_all(dest,len,"^"","\^"");
}

/*=============================== Вспомогательные функции ==================================*/

parse_results(Handle:sql_results, data[UserStruct]) {
	new parsed = 0;
	
	data[us_user_id] = SQL_ReadResult(sql_results, parsed);
	parsed += 1;
	SQL_ReadResult(sql_results, parsed, data[us_nickname], NICK_LENGTH);
	parsed += 1;
	SQL_ReadResult(sql_results, parsed, data[us_steam], STEAM_LENGTH);
	parsed += 1;
	SQL_ReadResult(sql_results, parsed, data[us_ip], IP_LENGTH);
	parsed += 1;
	SQL_ReadResult(sql_results, parsed, data[us_password], CACHE_LENGTH);
	parsed += 1;
	data[us_authfail] = _:SQL_ReadResult(sql_results, parsed);
	parsed += 1;
	data[us_authflags] = _:SQL_ReadResult(sql_results, parsed);
	parsed += 1;
	data[us_accessflags] = _:SQL_ReadResult(sql_results, parsed);
}

screen_object(const source[UserStruct], destination[UserStruct]) {
        mysql_escape_string(destination[us_nickname], NICK_LENGTH-1, source[us_nickname]);
        format(destination[us_nickname], NICK_LENGTH-1, "'%s'", destination[us_nickname]);
        
        mysql_escape_string(destination[us_steam], STEAM_LENGTH-1, source[us_steam]);
        format(destination[us_steam], STEAM_LENGTH-1, "'%s'", destination[us_steam]);
        
        mysql_escape_string(destination[us_password], CACHE_LENGTH-1, source[us_password]);
        format(destination[us_password], CACHE_LENGTH-1, "'%s'", destination[us_password]);
        
        mysql_escape_string(destination[us_ip], IP_LENGTH-1, source[us_ip]);
        format(destination[us_ip], IP_LENGTH-1, "'%s'", destination[us_ip]);
        destination[us_authflags] = source[us_authflags];
        destination[us_accessflags] = source[us_accessflags];
        destination[us_authfail] = source[us_authfail];
        destination[us_user_id] = source[us_user_id];
}

where_state(const data[UserStruct], where_clause[SQL_QLIM/2], separator[]) {
        new temp[UserStruct], flag = false;
        
        screen_object(data, temp);
        
        if(!auth_equal(data, us_user_id)) {
                if(flag)
                        format(where_clause, SQL_QLIM/2-1, "%s%s", where_clause, separator);
                        
                format(where_clause, SQL_QLIM/2-1, "%suid=%d", where_clause, temp[us_user_id]);
                flag = true; 
        }
        
        if(!auth_equal(data, us_nickname)) {
                if(flag)
                        format(where_clause, SQL_QLIM/2-1, "%s%s", where_clause, separator);
                
                format(where_clause, SQL_QLIM/2-1, "%snick=%s", where_clause, temp[us_nickname]);
                flag = true; 
        }
        
        if(!auth_equal(data, us_steam)) {
                if(flag)
                        format(where_clause, SQL_QLIM/2-1, "%s%s", where_clause, separator);
                        
                format(where_clause, SQL_QLIM/2-1, "%ssteam=%s", where_clause, temp[us_steam]);
                flag = true; 
        }
        
        if(!auth_equal(data, us_ip)) {
                if(flag)
                        format(where_clause, SQL_QLIM/2-1, "%s%s", where_clause, separator);
                        
                format(where_clause, SQL_QLIM/2-1, "%sip=%s", where_clause, temp[us_ip]);
                flag = true; 
        }
        
        if(!auth_equal(data, us_password)) {
                if(flag)
                        format(where_clause, SQL_QLIM/2-1, "%s%s", where_clause, separator);
                        
                format(where_clause, SQL_QLIM/2-1, "%spass=%s", where_clause, temp[us_password]);
                flag = true; 
        }
        
        if(!auth_equal(data, us_authfail)) {
                if(flag)
                        format(where_clause, SQL_QLIM/2-1, "%s%s", where_clause, separator);
                        
                format(where_clause, SQL_QLIM/2-1, "%sauth_fail=%d", where_clause, temp[us_authfail]);
                flag = true; 
        }
        
        if(!auth_equal(data, us_authflags)) {
                if(flag)
                        format(where_clause, SQL_QLIM/2-1, "%s%s", where_clause, separator);
                        
                format(where_clause, SQL_QLIM/2-1, "%sauth_flags=%d", where_clause, temp[us_authflags]);
                flag = true; 
        }
        
        if(!auth_equal(data, us_accessflags)) {
                if(flag)
                        format(where_clause, SQL_QLIM/2-1, "%s%s", where_clause, separator);
                        
                format(where_clause, SQL_QLIM/2-1, "%sflags=%d", where_clause, temp[us_accessflags]);
                flag = true; 
        }
}

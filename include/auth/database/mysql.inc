

#if defined _authorization_storage_interface_included
        #endinput
#endif
#define _authorization_storage_interface_included

#include <auth_core>
#include <sqlx> 


/*============================= Конфигурация базы данных ===================================*/
new const db_host[]     = "localhost";
new const db_username[] = "root";
new const db_password[] = "root";
new const db_database[] = "zombielite";
/*==========================================================================================*/


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
new const __AUTH_DELETE[] =  "DELETE FROM auth_system WHERE %s;";

/*=============================== Реализация взаимодействий ================================*/
storage_init() {
        new query[SQL_QLIM]; 
        new thread_info[ThreadData] = thread_proto;
        thread_info[useThread] = true;
        
        format(query, SQL_QLIM-1, __AUTH_CREATE, MAX_NAME_LENGTH, MAX_AUTHID_LENGTH, MAX_IP_LENGTH, PASSWORD_HASH_LENGTH);
        return mysql_exec(query, thread_info);
}
// user, thread_info
storage_create_user(data[UserStruct], thread_info[ThreadData] = thread_proto) {
        new query[SQL_QLIM]; query = __AUTH_INSERT; // Базовая строка запроса
        new temp[UserStruct];                       // Объект с экранированными данными
        new values[SQL_QLIM/2];                     // Отформатированная строка значений
        
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
        
        // Выполняем запрос на создание пользователя в таблице
        new Handle:h_results = mysql_exec(query, thread_info, "thread__storage_create");
        new last_id = -1;       // По умолчанию: если last_id=-1, то это потоковый запрос
        
        // Возвращаем -2, ибо проблемы с коннектом до БД
        if(h_results == Empty_Handle) {
                return -2;
        }
        
        // Если запрос не поточный, то получаем последний вставленный ID
        // К сожалению, может случиться косяк, если БД не вставит строку:
        // мы получим ID предыдущей записи.
        // На убунте возможно падение из за косяка драйвера мускуля D:<
        //if(!thread_info[useThread]) 
        //        last_id = SQL_GetInsertId(h_results);
                
        if(!thread_info[useThread]) {
                SQL_FreeHandle(h_results); 
	}
        
        return last_id;
}

storage_find_user(data[UserStruct], thread_info[ThreadData] = thread_proto) {
        new query[SQL_QLIM]; query = __AUTH_SELECT;     // Базовая строка запроса
        new temp[UserStruct];                           // Структура для хранения пользователя
        new where_clause[SQL_QLIM/2];                   // Уточнающая строка
        
        dump_userinfo(data);
        // Строим уточнающую строку
        where_state(data, where_clause, " AND ");
        
        // Собираем строку запроса
        format(query, SQL_QLIM-1, query, where_clause);
        
        new Handle:h_results = mysql_exec(query, thread_info, "thread__storage_read");
        
        // Возвращаем -2, ибо проблемы с коннектом до БД
        if(h_results == Empty_Handle) {
                return -2;
        }
        
        // Если запрос не поточный, то парсим результат
        if(!thread_info[useThread]) {
                // Заводим массив для сохранения всех данных, что попали в выборку
                new Array:results = ArrayCreate(UserStruct);
                
                // Парсим результаты в массив
                while(SQL_MoreResults(h_results)) {
		        parse_results(h_results, temp);
		        ArrayPushArray(results, temp);
                        SQL_NextRow(h_results);
	        } 
                ArrayDestroy(results);
                SQL_FreeHandle(h_results); 
	}
        
        // Слооожна! 
        // Условие: 
        // Если поточный запрос - возвращать -1, иначе - массив с результатами с лояльным тегом (_:)
        return (thread_info[useThread])? -1 : _:h_results;
}


storage_modify_user(user_id, data[UserStruct], thread_info[ThreadData] = thread_proto) {
        new query[SQL_QLIM]; query = __AUTH_UPDATE;     // Базовая строка запроса
        new set_statement[SQL_QLIM/2];                  // Строка параметров
        
        // Задаём строку параметров
        where_state(data, set_statement, ", ");
        
        // Строим строку запроса
        format(query, SQL_QLIM-1, query, set_statement, user_id);
        
        new Handle:h_results = mysql_exec(query, thread_info, "thread__storage_write");
        
        // Возвращаем -2, ибо проблемы с коннектом до БД
        if(h_results == Empty_Handle) {
                return -2;
        }
        if(!thread_info[useThread]) {
                SQL_FreeHandle(h_results); 
        }
        
        return (thread_info[useThread])? -1 : 1;
}

storage_delete_user(data[UserStruct], thread_info[ThreadData] = thread_proto) {
        new query[SQL_QLIM]; query = __AUTH_DELETE;
        new del_statement[SQL_QLIM/2];                  // Строка параметров
        
        // Задаём строку параметров
        where_state(data, del_statement, ", ");
        
        // Строим строку запроса
        format(query, SQL_QLIM-1, query, del_statement);
        
        new Handle:h_results = mysql_exec(query, thread_info, "thread__storage_delete");
        new affected_rows = SQL_AffectedRows(h_results);
        
        // Возвращаем -2, ибо проблемы с коннектом до БД
        if(h_results == Empty_Handle) {
                return -2;
        }
	
        if(!thread_info[useThread]) {
                SQL_FreeHandle(h_results); 
        }
        
        return (thread_info[useThread])? -1 : affected_rows;
}

/*=============================== Методы обратного вызова ==================================*/

public thread__storage_create(failstate, Handle:h_results, error[], errnum, thread_info[], size, Float:queuetime) {
        thread__debug(failstate, h_results, error, errnum, thread_info, size, queuetime);
        
        if(h_results == Empty_Handle)
                return;
        
        if(thread_info[TDFunction] < 0)
                return;
        
        switch(callfunc_begin_i(thread_info[TDFunction], thread_info[TDPlugin])) {
	        case 1: {
			callfunc_push_int(SQL_GetInsertId(h_results));
			if(thread_info[TDInfoFlags] > 0) 
			        callfunc_push_int(thread_info[TDInfoFlags]);
		        callfunc_end();
		        return;
	        }
	        case 0,-1,-2: {
	                return;
	        }
        }
}

public thread__storage_read(failstate, Handle:h_results, error[], errnum, thread_info[], size, Float:queuetime) {
        thread__debug(failstate, h_results, error, errnum, thread_info, size, queuetime);

        if(h_results == Empty_Handle)
                return;
        
        if(thread_info[TDFunction] < 0)
                return;
        
        switch(callfunc_begin_i(thread_info[TDFunction], thread_info[TDPlugin])) {
	        case 1: {
	                // Заводим массив для сохранения всех данных, что попали в выборку
                        new Array:results = ArrayCreate(UserStruct);
                        new temp[UserStruct];     // Структура для хранения пользователя
                        
                        // Парсим результаты в массив
                        while(SQL_MoreResults(h_results)) {
		                parse_results(h_results, temp);
                                dump_userinfo(temp);
		                ArrayPushArray(results, temp);
                                SQL_NextRow(h_results);
	                } 
			callfunc_push_int(_:results);
			if(thread_info[TDInfoFlags] > 0) 
			        callfunc_push_int(thread_info[TDInfoFlags]);
		        callfunc_end();
		        return;
	        }
	        case 0,-1,-2: {
	                return;
	        }
        }
}

public thread__storage_update(failstate, Handle:h_results, error[], errnum, thread_info[], size, Float:queuetime) {
        thread__debug(failstate, h_results, error, errnum, thread_info, size, queuetime);

        if(h_results == Empty_Handle)
                return;
        
        if(thread_info[TDFunction] < 0)
                return;
        
        switch(callfunc_begin_i(thread_info[TDFunction], thread_info[TDPlugin])) {
	        case 1: {
			callfunc_push_int(1);
			if(thread_info[TDInfoFlags] > 0) 
			        callfunc_push_int(thread_info[TDInfoFlags]);
		        callfunc_end();
		        return;
	        }
	        case 0,-1,-2: {
	                return;
	        }
        }
}

public thread__storage_delete(failstate, Handle:h_results, error[], errnum, thread_info[], size, Float:queuetime) {
        thread__debug(failstate, h_results, error, errnum, thread_info, size, queuetime);

        if(h_results == Empty_Handle)
                return;
        
        if(thread_info[TDFunction] < 0)
                return;
           
        switch(callfunc_begin_i(thread_info[TDFunction], thread_info[TDPlugin])) {
	        case 1: {
			callfunc_push_int(SQL_AffectedRows(h_results));
			if(thread_info[TDInfoFlags] > 0) 
			        callfunc_push_int(thread_info[TDInfoFlags]);
		        callfunc_end();
		        return;
	        }
	        case 0,-1,-2: {
	                return;
	        }
        }
}

public thread__debug(failstate, Handle:query, error[], errnum, data[], size, Float:queuetime) {
        if(failstate != TQUERY_SUCCESS)    
                logger(ERROR_SQL_FAILED, errnum, error);
}

/*==================================== Стоковые функции ====================================*/

// Метод, исполняющий запрос (поточный, последовательный - не важно)
stock any:mysql_exec(const sql_query[], thread_info[ThreadData], callback[] = "mysql_query_handler") {
        new s_Error[SQL_QLIM/2], i_Error;
        static database[SQLD];
        database[sqld_tuple] = SQL_MakeDbTuple(db_host, db_username, db_password, db_database);
        
        // Дебажируем вывод :3
        logger(DEBUG_SQL, sql_query);
        if(thread_info[useThread])
                logger(DEBUG_SQL, "Using threading...");
        
        if(thread_info[useThread]) {
                SQL_ThreadQuery(database[sqld_tuple], callback, sql_query, thread_info, ThreadData);
        }
        else {
                        
                database[sqld_instance] = SQL_Connect(database[sqld_tuple], i_Error, s_Error, charsmax(s_Error));
                new Handle:result = SQL_PrepareQuery(database[sqld_instance], sql_query);
                
                if(!SQL_Execute (result)) {
                        logger(ERROR_SQL_FAILED, SQL_QueryError(result, s_Error, charsmax(s_Error)), s_Error);
                }
                return result;
        }
        
        mysql_close(database);

        return true;
}

// Унифицированный приемщик результатов, если нужно было только выполнить запрос
public mysql_query_handler(failstate, Handle:query, error[], errnum, data[], size, Float:queuetime) {
        if(failstate != TQUERY_SUCCESS)    logger(DEBUG_SQL, error);
}

// Убийца всех хендлеров :3
stock mysql_close(instance[SQLD]) {
        if(instance[sqld_instance] != Empty_Handle)
                SQL_FreeHandle(instance[sqld_instance]);
        if(instance[sqld_tuple] != Empty_Handle)
                SQL_FreeHandle(instance[sqld_tuple]); 
}

// Избегаем опасных символов в запросах
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

// Парсер результатов в структуру
parse_results(Handle:sql_results, data[UserStruct]) {
	new parsed = 0;
	
	data[us_user_id] = SQL_ReadResult(sql_results, parsed++);
	SQL_ReadResult(sql_results, parsed++, data[us_nickname], MAX_NAME_LENGTH);
	SQL_ReadResult(sql_results, parsed++, data[us_steam], MAX_AUTHID_LENGTH);
	SQL_ReadResult(sql_results, parsed++, data[us_ip], MAX_IP_LENGTH);
	SQL_ReadResult(sql_results, parsed++, data[us_password], PASSWORD_HASH_LENGTH);
	data[us_authfail] = _:SQL_ReadResult(sql_results, parsed++);
	data[us_authflags] = _:SQL_ReadResult(sql_results, parsed++);
	data[us_accessflags] = _:SQL_ReadResult(sql_results, parsed++);
}

// Копируем структуру и экранируем её строки
screen_object(const source[UserStruct], destination[UserStruct]) {
        mysql_escape_string(destination[us_nickname], MAX_NAME_LENGTH-1, source[us_nickname]);
        format(destination[us_nickname], MAX_NAME_LENGTH-1, "'%s'", destination[us_nickname]);
        
        mysql_escape_string(destination[us_steam], MAX_AUTHID_LENGTH-1, source[us_steam]);
        format(destination[us_steam], MAX_AUTHID_LENGTH-1, "'%s'", destination[us_steam]);
        
        mysql_escape_string(destination[us_password], PASSWORD_HASH_LENGTH-1, source[us_password]);
        format(destination[us_password], PASSWORD_HASH_LENGTH-1, "'%s'", destination[us_password]);
        
        mysql_escape_string(destination[us_ip], MAX_IP_LENGTH-1, source[us_ip]);
        format(destination[us_ip], MAX_IP_LENGTH-1, "'%s'", destination[us_ip]);
        destination[us_authflags] = source[us_authflags];
        destination[us_accessflags] = source[us_accessflags];
        destination[us_authfail] = source[us_authfail];
        destination[us_user_id] = source[us_user_id];
}

// Построитель запроса
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

/*
CREATE TABLE `auth_system` (
  `uid` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `nick` varchar(34) DEFAULT NULL,
  `steam` varchar(32) DEFAULT NULL,
  `ip` varchar(20) DEFAULT NULL,
  `pass` varchar(70) DEFAULT NULL,
  `auth_fail` int(3) unsigned DEFAULT '0',
  `auth_flags` int(10) unsigned DEFAULT '0',
  `flags` int(10) unsigned DEFAULT '0',
  PRIMARY KEY (`uid`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8
*/
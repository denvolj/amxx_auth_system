/*============================================================================================
	
	---------------------------------
	-*- [ZL] Auth system core     -*-
	---------------------------------
	
	Система регистрации и авторизации.
	Описание:
		Плагин реализовывает базовые функции регистрации и авторизации по никнейму.
	Настройки плагина гибкие, пользователь может сам выбрать по каким параметрам производить
	аутентификацию. На данный момент это STEAMID, IP, PASSWORD.
	
	Реализованные фичи:
	 - Автоматическое создание таблицы при регистрации плагина
	 - Авторизация/регистрация
	 - Гибкий API плагина, позволяющий производить основные операции с пользователями
	 - Меню плагина, позволяющее выбрать параметры аутентификации
	
============================================================================================*/


#include <amxmodx>
#include <amxmisc>
#include <hamsandwich>
#include <sqlx> 
#include <zl_auth_core>
#include <zl_dynamic_menu>
#include <mysql_helper>
#include <chatcolor>

/*===================================== Блок констант ======================================*/
#define PLUG_OBJNAME			"AuthCore"
#define PLUG_VERSION			"1.0"
#define PLUG_CREATOR			"Boec[SpecOPs]"


/*==================================== Блок переменных =====================================*/
new fwd_userLogIn, fwd_userLogOut, fwd_userRegister;

new g_users_cached[33][userRecord];
new g_users_auth_params[33][authPropeties];

/*================== Первичная инициализация и завершение работы плагина ===================*/

new const ZL_AUTH_CREATE[] =	                   
	"	CREATE TABLE IF NOT EXISTS zl_auth_users    \
		(                                           \
			uID INT(10) AUTO_INCREMENT PRIMARY KEY, \
			username VARCHAR(128) NOT NULL UNIQUE,	\
			password VARCHAR(34) DEFAULT NULL,		\
			steamID VARCHAR(64) DEFAULT NULL,       \
			IP VARCHAR(18) DEFAULT NULL,			\
			level INT(5) DEFAULT 1					\
		) ENGINE = InnoDB;                          \
	";
new const ZL_AUTH_SELECT[]	=	"SELECT * FROM zl_auth_users WHERE %s;"
new const ZL_AUTH_INSERT[]	=	"INSERT INTO zl_auth_users (%s) VALUES(%s);"
new const ZL_AUTH_UPDATE[]	=	"UPDATE zl_auth_users SET %s WHERE %s;"
new const ZL_AUTH_DELETE[]	=	"DELETE FROM zl_auth_users WHERE %s;"


public plugin_init() {
	register_plugin(PLUG_OBJNAME, PLUG_VERSION, PLUG_CREATOR);
	
	mysql_db_init();
	
	register_clcmd("say /reg", "menu__register");
	register_clcmd("say reg", "menu__register");
	register_clcmd("reg", "menu__register");
	
	fwd_userLogIn = CreateMultiForward("zl_auth_userLogIn", ET_IGNORE, FP_CELL, FP_CELL);
	fwd_userLogOut = CreateMultiForward("zl_auth_userLogOut", ET_IGNORE, FP_CELL, FP_CELL);
	fwd_userRegister = CreateMultiForward("zl_auth_userRegister", ET_IGNORE, FP_CELL, FP_CELL);
}

/*
public item_register() {
	cs_dynamicmenu_additem("Menu", "Профайл", "menu__register", -1, get_plugID("MainMenu"));
}
*/

public plugin_natives() {
	register_native("zl_auth_adduser", "native__add");
	register_native("zl_auth_setuser", "native__set");
	register_native("zl_auth_deluser", "native__del");
	register_native("zl_auth_getuser", "native__get");
	register_native("zl_auth_getuser_by_pid", "native__get_by_pid", 1);
	register_native("zl_auth_cached_get", "native__get_cached");
	register_native("zl_auth_cached_set", "native__set_cached");
}

public mysql_db_init() {
	new instance[SQLD];	
	
	instance = mysql_connect(g_host, g_user, g_pass, g_database);
	
	mysql_exec(ZL_AUTH_CREATE, instance);	
	mysql_close(instance);
}

public plugin_end() {

}

/*========================================= События ========================================*/
public client_putinserver(id) {
	
	new name[NAME_MAXLEN];
	get_user_name ( id, name, NAME_MAXLEN);
	
	zl_auth_getuser(zl_userName, name, g_users_cached[id]);
	
	if(strlen(g_users_cached[id][ur_username]) == 0) {
		g_users_cached[id] = getPrototype();
		g_users_cached[id][ur_username] = name;
		g_users_cached[id][ur_logStatus] = asNotRegistered;
	} else {
		authorize_user(id);
	}
	
	g_users_auth_params[id][ap_IP] = 	 (strlen(g_users_cached[id][ur_IP]) != 0);
	g_users_auth_params[id][ap_PASSWD] = (strlen(g_users_cached[id][ur_password]) != 0);
	g_users_auth_params[id][ap_SID] =    (strlen(g_users_cached[id][ur_steamID]) != 0);
}

public client_disconnect(id) {
	unauthorize_user(id);
}

/*==================================== Команды сервера =====================================*/
public crud() {
	new user[userRecord];
	zl_auth_adduser(zl_userName, "HexedOwner", zl_userLevel, 15);
	zl_auth_setuser(zl_userName, "HexedOwner", zl_userLevel, 1024);
	zl_auth_getuser(zl_userName, "TestUser", user);

	zl_auth_deluser(zl_userName, "HexedOwner");
}

/*================================== Процедуры авторизации =================================*/
public authorize_user(id) {
	new currUser[userRecord];
	new success = true;
	new name[NAME_MAXLEN];
	get_user_name ( id, name, NAME_MAXLEN);
	
	if(strlen(g_users_cached[id][ur_steamID]) > 0) {
		get_user_authid(id, currUser[ur_steamID], STEAMID_MAXLEN);
		if(strcmp(currUser[ur_steamID], g_users_cached[id][ur_steamID])) {
			success = false;
		}
	}
	if(strlen(g_users_cached[id][ur_IP]) > 0) {
		get_user_ip(id, currUser[ur_IP], IP_MAXLEN, 1);
		if(strcmp(currUser[ur_IP], g_users_cached[id][ur_IP])) {
			success = false;
		}
	}
	if(strlen(g_users_cached[id][ur_password]) > 0) {
		new pass[PASS_MAXLEN];
		
		get_user_info(id, ZL_INFO_PASS, pass, PASS_MAXLEN);
		format(currUser[ur_password], MD5_MAXLEN, "%s", get_md5(pass));
		if(strcmp(currUser[ur_password], g_users_cached[id][ur_password])) {
			success = false;
		}
	}
	
	if(success) {
		new ret;
		g_users_cached[id][ur_logStatus] = asAuthorized;
		ExecuteForward(fwd_userLogIn, ret, id, g_users_cached[id][ur_uID]);
	} else {
		g_users_cached[id] = getPrototype();
		g_users_cached[id][ur_username] = name;
		g_users_cached[id][ur_logStatus] = asNotAuthorized;
	}
}

public unauthorize_user(id) {
	new ret;
	switch(g_users_cached[id][ur_logStatus]) {
		case asAuthorized: {
			apply(id)
			zl_auth_setuser(
				zl_userID, g_users_cached[id][ur_uID],
				zl_userName, g_users_cached[id][ur_username],
				zl_userIP, g_users_cached[id][ur_IP],
				zl_userSteam, g_users_cached[id][ur_steamID],
				zl_userPass, g_users_cached[id][ur_password],
				zl_userLevel, g_users_cached[id][ur_level]
			);
			ExecuteForward(fwd_userLogOut, ret, id, g_users_cached[id][ur_uID]);
		}
		case asNotRegistered: {
			zl_auth_adduser(
				zl_userName, g_users_cached[id][ur_username],
				zl_userIP, g_users_cached[id][ur_IP],
				zl_userSteam, g_users_cached[id][ur_steamID],
				zl_userPass, g_users_cached[id][ur_password],
				zl_userLevel, g_users_cached[id][ur_level]
			);
			
			zl_auth_getuser(zl_userName, g_users_cached[id][ur_username], g_users_cached[id]);
			
			ExecuteForward(fwd_userRegister, ret, id, g_users_cached[id][ur_uID]);
		}
	}
}

public apply(id) {
	static message[192]
	if(!g_users_auth_params[id][ap_IP]) {
		g_users_cached[id][ur_IP] = "";
	} else {
		get_user_ip(id, g_users_cached[id][ur_IP], IP_MAXLEN, 1);
	}
	
	if(!g_users_auth_params[id][ap_SID]) {
		g_users_cached[id][ur_steamID] = "";
	} else {
		get_user_authid(id, g_users_cached[id][ur_steamID], STEAMID_MAXLEN);
	}
	
	if(!g_users_auth_params[id][ap_PASSWD]) {
		g_users_cached[id][ur_password] = "";
	} else {
		new password[MD5_MAXLEN];
		new r_int
		
		r_int = get_user_info(id, ZL_INFO_PASS, password, MD5_MAXLEN-1)
		if(r_int == 0) {  	// Password not exist, generating password by cache
			r_int = random(99999999999);					// gen random int
			num_to_str(r_int, password, MD5_MAXLEN-1);		// int to string for md5 cache
			copy(password, 16, get_md5(password))			// do md5
			set_user_info(id, ZL_INFO_PASS, password);	// save pass to client 
			console_cmd(id, "%s %s", ZL_INFO_PASS, password);
			client_print(id, print_console, "#####################################")
			client_print(id, print_console, "# Your password: ^"%s^"", password)
			client_print(id, print_console, "# Print in console: setinfo %s %s", ZL_INFO_PASS, password)
			client_print(id, print_console, "#####################################")
			g_users_cached[id][ur_password] = get_md5(password);	// save md5 to server
		} else {  		// Password exist
			g_users_cached[id][ur_password] = get_md5(password)// save md5 to server
			console_cmd(id, "%s %s", ZL_INFO_PASS, password);
			client_print(id, print_console, "#####################################")
			client_print(id, print_console, "# Your password: ^"%s^"", password)
			client_print(id, print_console, "# Print in console: setinfo %s %s", ZL_INFO_PASS, password)
			client_print(id, print_console, "#####################################")
		}
		
		ColorChat(id, DontChange, "^1[^4%s^1]^2Your password ready. Print ^4setinfo %s ^"%s^"^1 in your console.", PLUG_OBJNAME, ZL_INFO_PASS, password)
	}		
}

/*========================================== Меню ==========================================*/
public menu__register(id)
{	
	if(!is_user_connected(id))
		return PLUGIN_HANDLED;
	new menu_header[256];

	switch(g_users_cached[id][ur_logStatus]) {
		case asAuthorized: {
			add(menu_header, 256, "\r[\wZombieLite:Auth\r] \wАвторизован^n");
		}
		case asNotAuthorized: {
			add(menu_header, 256, "\r[\wZombieLite:Auth\r] \rНе авторизован^n");
		}
		case asNotRegistered: {
			add(menu_header, 256, "\r[\wZombieLite:Auth\r] \rНе зарегистрирован^n");
		}
	}
	add(menu_header, 256, "\yНастройки профиля:^n");
	add(menu_header, 256, "->Проверки аутентификации");

	new menu = menu_create(menu_header, "h_zl_auth_register");

	if(!g_users_auth_params[id][ap_IP]) {
		menu_additem(menu, "\yIP адрес (отключено)", "", 0);
	} else {
		menu_additem(menu, "\yIP адрес (включено)", "", 0);
	}
	
	if(!g_users_auth_params[id][ap_SID]) {
		menu_additem(menu, "\ySteamID (отключено)", "", 0);
	} else {
		menu_additem(menu, "\ySteamID (включено)", "", 0);
	}
	
	if(!g_users_auth_params[id][ap_PASSWD]) {
		menu_additem(menu, "\yПароль (отключено)", "", 0); 
	} else {
		menu_additem(menu, "\yПароль (включено)", "", 0);
	}
	
	menu_additem(menu, "\yСохранить", "", 0);	
	
	menu_setprop(menu, MPROP_PERPAGE, 7);
	menu_setprop(menu, MPROP_NUMBER_COLOR, "\r");

	menu_display(id, menu, 0);

	return PLUGIN_HANDLED;
}

/*==================================== Меню обработчики ====================================*/

public h_zl_auth_register(id, menu, item)
{
	if(item == MENU_EXIT)
	{
		menu_cancel(id);
		return PLUGIN_HANDLED;
	}

	new command[6], name[64], access, callback;

	menu_item_getinfo(menu, item, access, command, sizeof command - 1, name, sizeof name - 1, callback);

	switch(item)
	{
		case 0: {
			g_users_auth_params[id][ap_IP] = !g_users_auth_params[id][ap_IP];
		}
		case 1: {
			g_users_auth_params[id][ap_SID] = !g_users_auth_params[id][ap_SID];
		}
		case 2: {
			g_users_auth_params[id][ap_PASSWD] = !g_users_auth_params[id][ap_PASSWD];
		}
		case 3: {
			apply(id);
			menu_cancel(id);
			
			return PLUGIN_HANDLED;
		}
	}

	menu_cancel(id);
	menu__register(id);

	return PLUGIN_HANDLED;
}


/*===================================== Нативы плагина =====================================*/

public native__set(p_id, args) {
	if(args < 3)	// param, value[, param, value[, ...]]
        return false;
	new field = 0;
	new query[SQL_QLIM], s_name[NAME_MAXLEN], value_s[VL_MAXLENGTH];
	new value_tmp[VL_MAXLENGTH];
	new instance[SQLD];
	new WHERE_CLAUSE[128];
	
	instance = mysql_connect(g_host, g_user, g_pass, g_database);
	
	field = get_param_byref(1);	
	if(field == zl_userID) {
		WHERE_CLAUSE = "%s=%d";
		format(WHERE_CLAUSE, 128, WHERE_CLAUSE, get_fields_string(field), get_param_byref(2));
	} else if(field == zl_userName) {
		WHERE_CLAUSE = "%s='%s'";
		get_string(2, s_name, NAME_MAXLEN);
		SQL_QuoteString(instance[sqld_instance], s_name, NAME_MAXLEN, s_name);
		format(WHERE_CLAUSE, 128, WHERE_CLAUSE, get_fields_string(field), s_name);
	} else return false;
		
	for (new i = 1, ag = args / 2; i < ag; i++) {
		if(i >= 2) {
			add(value_s, VL_MAXLENGTH, ", ");
		}
		
		field = get_param_byref(i*2+1);
		if(field == zl_userName) {
			get_string(i*2+2, s_name, NAME_MAXLEN);
			SQL_QuoteString(instance[sqld_instance], s_name, NAME_MAXLEN, s_name);
			
			format(value_s, VL_MAXLENGTH, "%susername='%s'", value_s, s_name);
		}
		else if(field == zl_userPass) {
			get_string(i*2+2, value_tmp, VL_MAXLENGTH);
			if(strcmp(value_tmp, "") == 0) {
				format(value_s, VL_MAXLENGTH, "%spassword=NULL", value_s);
			} else {
				format(value_s, VL_MAXLENGTH, "%spassword='%s'", value_s, value_tmp);
			}
		} 
		else if(field == zl_userSteam) {
			get_string(i*2+2, value_tmp, VL_MAXLENGTH);
			format(value_s, VL_MAXLENGTH, "%ssteamID='%s'", value_s, value_tmp);
		} 
		else if(field == zl_userIP) {
			get_string(i*2+2, value_tmp, VL_MAXLENGTH);
			format(value_s, VL_MAXLENGTH, "%sIP='%s'", value_s, value_tmp);
		} 
		else if(field == zl_userLevel) {
			format(value_s, VL_MAXLENGTH, "%slevel=%d", value_s, get_param_byref(i*2+2));
		} 
	}
	
	format(query, SQL_QLIM, ZL_AUTH_UPDATE, value_s, WHERE_CLAUSE);
	
	mysql_exec(query, instance);
	
	mysql_close(instance);
	
	return true
}

public native__get_by_pid(pID) {
	return g_users_cached[pID][ur_uID];
}

// Получить пользователя по нику/по id в системе.
public native__get(p_id, args) {
	new results[userRecord];
	if(args < 2)	// param, value[, param, value[, ...]]
        return false;
		
	new query[SQL_QLIM];
	new field = get_param_byref(1);
	new instance[SQLD];	
	new s_name[NAME_MAXLEN]
	new WHERE_CLAUSE[128];
	
	instance = mysql_connect(g_host, g_user, g_pass, g_database);
	if(field == zl_userID) {
		WHERE_CLAUSE = "%s=%d";
		format(WHERE_CLAUSE, 128, WHERE_CLAUSE, get_fields_string(field), get_param_byref(2));
	} else if(field == zl_userName) {
		WHERE_CLAUSE = "%s='%s'";
		get_string(2, s_name, NAME_MAXLEN);
		SQL_QuoteString(instance[sqld_instance], s_name, NAME_MAXLEN, s_name);
		format(WHERE_CLAUSE, 128, WHERE_CLAUSE, get_fields_string(field), s_name);
	} else return false;
	
	format(query, SQL_QLIM, ZL_AUTH_SELECT, WHERE_CLAUSE)
	
	new Handle:query_results = mysql_exec(query, instance);
	
	if(SQL_MoreResults(query_results)) {
		results = parse_results(query_results);	
	}
	
	set_array(3, results, userRecord);
	
	SQL_FreeHandle(query_results);
	mysql_close(instance);
	
	return true;
}

public native__add(p_id, args) {
	if(args < 2)	// param, value[, param, value[, ...]]
        return false;
	new field = 0;
	new query[SQL_QLIM] = "", s_name[NAME_MAXLEN] = "", value_s[VL_MAXLENGTH] = "", field_s[FD_MAXLENGTH]= "";
	new value_tmp[VL_MAXLENGTH] = "";
	new instance[SQLD];	
	
	instance = mysql_connect(g_host, g_user, g_pass, g_database);
	
	for (new i = 0, ag = args / 2; i < ag; i++) {
		if(i >= 1) {
			add(field_s, FD_MAXLENGTH, ", ");
			add(value_s, VL_MAXLENGTH, ", ");
		}
	
		field = get_param_byref(i*2+1);
		if(field == zl_userName) {
			format(field_s, FD_MAXLENGTH, "%susername", field_s);
			get_string(i*2+2, s_name, NAME_MAXLEN);
			SQL_QuoteString(instance[sqld_instance], s_name, NAME_MAXLEN, s_name);
			
			format(value_s, VL_MAXLENGTH, "%s'%s'", value_s, s_name);
		}
		else if(field == zl_userPass) {
			format(field_s, FD_MAXLENGTH, "%spassword", field_s);
			get_string(i*2+2, value_tmp, VL_MAXLENGTH);
			if(strcmp(value_tmp, "") == 0) {
				format(value_s, VL_MAXLENGTH, "%sNULL", value_s);
			} else {
				format(value_s, VL_MAXLENGTH, "%s'%s'", value_s, get_md5(value_tmp));
			}
		} 
		else if(field == zl_userSteam) {
			format(field_s, FD_MAXLENGTH, "%ssteamID", field_s);
			get_string(i*2+2, value_tmp, VL_MAXLENGTH);
			format(value_s, VL_MAXLENGTH, "%s'%s'", value_s, value_tmp);
		} 
		else if(field == zl_userIP) {
			format(field_s, FD_MAXLENGTH, "%sIP", field_s);
			get_string(i*2+2, value_tmp, VL_MAXLENGTH);
			format(value_s, VL_MAXLENGTH, "%s'%s'", value_s, value_tmp);
		} 
		else if(field == zl_userLevel) {
			format(field_s, FD_MAXLENGTH, "%slevel", field_s);
			format(value_s, VL_MAXLENGTH, "%s%d", value_s, get_param_byref(i*2+2));
		} 
	}
	
	format(query, SQL_QLIM, ZL_AUTH_INSERT, field_s, value_s);
	
	mysql_exec(query, instance);
	
	mysql_close(instance);
	
	return true;
}


public native__del(p_id, args) {
	if(args < 2)	// param, value[, param, value[, ...]]
        return false;
				
	new query[SQL_QLIM];
	new field = get_param_byref(1);
	new instance[SQLD];	
	new s_name[NAME_MAXLEN]
	new WHERE_CLAUSE[128];
	
	instance = mysql_connect(g_host, g_user, g_pass, g_database);
	if(field == zl_userID) {
		WHERE_CLAUSE = "%s=%d";
		format(WHERE_CLAUSE, 128, WHERE_CLAUSE, get_fields_string(field), get_param_byref(2));
	} else if(field == zl_userName) {
		WHERE_CLAUSE = "%s='%s'";
		get_string(2, s_name, NAME_MAXLEN);
		SQL_QuoteString(instance[sqld_instance], s_name, NAME_MAXLEN, s_name);
		format(WHERE_CLAUSE, 128, WHERE_CLAUSE, get_fields_string(field), s_name);
	} else return true;
	
	format(query, SQL_QLIM, ZL_AUTH_DELETE, WHERE_CLAUSE);
	
	mysql_exec(query, instance);
	
	mysql_close(instance);
	
	return true
}

public native__get_cached(p_id, args) {
	new pID = get_param_byref(1);
	set_array(2, g_users_cached[pID], userRecord);
}

public native__set_cached(p_id, args) {
	new pID = get_param_byref(1);
	get_array(2, g_users_cached[pID], userRecord);
}

/*============================ Функции асинхронной работы с БД =============================*/

public default_async(FailState, Handle:Query, error[], err, data[], size, Float:querytime){
	if(FailState != TQUERY_SUCCESS)	{
		log_amx("sql error: %d (%s)", err, error)
		return
	}
	if( SQL_NumResults(Query) > 0 ) {
		return;
	}

	SQL_FreeHandle(Query);
}

/*=========================== Построители запросов к базе данных ===========================*/

parse_results(Handle:sql_results) {
	new results[userRecord];
	new parsed = 0;
	
	results[ur_uID] = SQL_ReadResult(sql_results, parsed);
	parsed += 1;
	SQL_ReadResult(sql_results, parsed, results[ur_username], NAME_MAXLEN);
	parsed += 1;
	SQL_ReadResult(sql_results, parsed, results[ur_password], MD5_MAXLEN);
	parsed += 1;
	SQL_ReadResult(sql_results, parsed, results[ur_steamID], STEAMID_MAXLEN);
	parsed += 1;
	SQL_ReadResult(sql_results, parsed, results[ur_IP], IP_MAXLEN);
	parsed += 1;
	results[ur_level] = SQL_ReadResult(sql_results, parsed);
	
	return results;
}

get_fields_string(fields) {
	new outstring[FD_MAXLENGTH];
	new flag = false;
	
	if(fields & zl_userID) {
		if(flag) add(outstring, VL_MAXLENGTH, ", "); 
		flag = true;
		format(outstring, VL_MAXLENGTH, "%suID", outstring);
	} 
	else if(fields & zl_userName) {
		if(flag) add(outstring, VL_MAXLENGTH, ", "); 
		flag = true;
		format(outstring, VL_MAXLENGTH, "%susername", outstring);
	} 
	else if(fields & zl_userPass) {
		if(flag) add(outstring, VL_MAXLENGTH, ", "); 
		flag = true;
		format(outstring, VL_MAXLENGTH, "%spassword", outstring);
	} 
	else if(fields & zl_userSteam) {
		if(flag) add(outstring, VL_MAXLENGTH, ", ");
		flag = true;
		format(outstring, VL_MAXLENGTH, "%ssteamID", outstring);
	} 
	else if(fields & zl_userIP) {
		if(flag) add(outstring, VL_MAXLENGTH, ", "); 
		flag = true;
		format(outstring, VL_MAXLENGTH, "%sIP", outstring);
	} 
	else if(fields & zl_userLevel) {
		if(flag) add(outstring, VL_MAXLENGTH, ", "); 
		flag = true;
		format(outstring, VL_MAXLENGTH, "%slevel", outstring);
	} 
	
	return outstring;
}

get_values_string(fields, values[userRecord], Handle:instance) {
	new outstring[VL_MAXLENGTH];

	new flag = false;
	
	if(fields & zl_userID) {
		if(flag) add(outstring, VL_MAXLENGTH, ","); 
		flag = true;
		format(outstring, VL_MAXLENGTH, "%s%d", outstring, values[ur_uID]);
	} 
	else if(fields & zl_userName) {
		if(flag) add(outstring, VL_MAXLENGTH, ","); 
		flag = true;
		format(outstring, VL_MAXLENGTH, "%s'%s'", outstring, mysql_screen_chars(values[ur_username], instance);
	} 
	else if(fields & zl_userPass) {
		if(flag) add(outstring, VL_MAXLENGTH, ","); 
		flag = true;
		format(outstring, VL_MAXLENGTH, "%s'%s'", outstring, get_md5(values[ur_password]));
	} 
	else if(fields & zl_userSteam) {
		if(flag) add(outstring, VL_MAXLENGTH, ","); 
		flag = true;
		format(outstring, VL_MAXLENGTH, "%s'%s'", outstring, values[ur_steamID]);
	} 
	else if(fields & zl_userIP) {
		if(flag) add(outstring, VL_MAXLENGTH, ","); 
		flag = true;
		format(outstring, VL_MAXLENGTH, "%s'%s'", outstring, values[ur_IP]);
	} 
	else if(fields & zl_userLevel) {
		if(flag) add(outstring, VL_MAXLENGTH, ","); 
		flag = true;
		format(outstring, VL_MAXLENGTH, "%s%d", outstring, values[ur_level]);
	} 
	return outstring;
}

/*================================== Прочие методы плагина =================================*/

stock get_md5(const text[])
{
    new encrypted[34]
    md5(text,encrypted)
     
    return encrypted;
}

stock user_print(user[userRecord]) {
	server_print("uID: %d", user[ur_uID]);
	server_print("Username: %s", user[ur_username]);
	server_print("steamID: %s", user[ur_steamID]);
	server_print("Password: %s", user[ur_password]);
	server_print("IP: %s", user[ur_IP]);
	server_print("level: %d", user[ur_level]);
	server_print("Auth: %d", user[ur_logStatus]);
}
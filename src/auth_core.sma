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

#pragma semicolon 1;

#include <amxmodx>
#include <auth_core>
#include <auth/database/mysql>


/*===================================== Блок констант ======================================*/
#define PLUG_OBJNAME			"AuthCore"
#define PLUG_VERSION			"1.0.0"
#define PLUG_CREATOR			"Boec[SpecOPs]"


/*==================================== Блок переменных =====================================*/
new fwd_check, fwd_status_change;
new players_cache[33][UserStruct];

new AuthFlags:auth_flag = AFLAG_NICK;
new pass_key[5] = "_pw";
new sault_cache[CACHE_LENGTH] = "LAKFaksldfjoIU(*#@UEDJIO";

/*================== Первичная инициализация и завершение работы плагина ===================*/

public plugin_init() {
	register_plugin(PLUG_OBJNAME, PLUG_VERSION, PLUG_CREATOR);
	
	fwd_check = CreateMultiForward("auth_check", ET_IGNORE, FP_CELL, FP_CELL, FP_CELL, FP_CELL);
	fwd_status_change = CreateMultiForward("auth_status_change", ET_IGNORE, FP_CELL, FP_CELL, FP_CELL, FP_CELL);
	
	cache_string(sault_cache, sault_cache);           // Покупаем соль...
	database_init();
}

public plugin_natives() {
	register_native("auth_player_status", "native__status", true);
	register_native("auth_get_byplayer","native__get_byplayer", true);
	register_native("auth_adduser",     "native__adduser", true);
	register_native("auth_getuser",     "native__getuser", true);
	register_native("auth_deluser",     "native__deluser", true);
	register_native("auth_usermod",     "native__usermod", true);
	register_native("auth_get_playerinfo","native__get_playerinfo", true);
	register_native("auth_set_playerinfo","native__set_playerinfo", true);
	register_native("auth_flush_playerinfo","native__flush_playerinfo", true);
	register_native("auth_force_login", "native__forcelogin", true);
	register_native("auth_force_logout","native__forcelogout", true);
}

/*
database_create_user(data[UserStruct]) {
        players_cache[0] = data;
}

database_find_user(data[UserStruct]) {
        data = players_cache[0];
}

database_modify_user(user_id, data[UserStruct]) {
        players_cache[user_id] = data;
}

database_delete_user(user_id) {
        new user[UserStruct] = user_proto_default;
        players_cache[user_id] = user;
}*/

/*===================================== Нативы плагина =====================================*/
public AuthStatus:native__status(p_id) {
        return players_cache[p_id][us_authstatus];
}

public native__get_byplayer(p_id, data[UserStruct]) {
        data = players_cache[p_id];
}

public native__adduser(user_id, 
                       username[NICK_LENGTH], 
                       steam[STEAM_LENGTH], 
                       ip[IP_LENGTH], 
                       password[CACHE_LENGTH], 
                       AuthFailActions:authfail, AuthFlags:authflags, accessflags, 
                       data[UserStruct]) {
        
        // Парсим данные в структуру data
        if(strcmp(username, " ") == 1) data[us_nickname] = username;
        if(strcmp(steam, " ") == 1) data[us_steam] = steam;
        if(strcmp(ip, " ") == 1) data[us_ip] = ip;
        if(strcmp(password, " ") == 1) {
                data[us_password] = password;
        }
        if(user_id > 0) data[us_user_id] = user_id;
        if(authfail != AFAIL_NULL) data[us_authfail] = _:authfail;
        if(authflags != AFLAG_NULL) data[us_authflags] = _:authflags;
        if(accessflags != -1) data[us_accessflags] = accessflags;
        
        cache_string(data[us_password], sault_cache);
        
        database_create_user(data);
}

public native__getuser(user_id, username[NICK_LENGTH], steam[STEAM_LENGTH], ip[IP_LENGTH], password[CACHE_LENGTH], data[UserStruct]) {
        data[us_user_id] = user_id;
        data[us_nickname] = username;
        data[us_steam] = steam;
        data[us_ip] = ip;
        data[us_password] = password;
        
        database_find_user(data);
}

public native__deluser(user_id) {
        database_delete_user(user_id);
}

public native__usermod(user_id, 
                       username[NICK_LENGTH], 
                       steam[STEAM_LENGTH], 
                       ip[IP_LENGTH], 
                       password[CACHE_LENGTH], 
                       AuthFailActions:authfail, AuthFlags:authflags, accessflags, 
                       data[UserStruct]) {
        // Парсим данные в структуру data
        if(strcmp(username, " ") == 1) data[us_nickname] = username;
        if(strcmp(steam, " ") == 1) data[us_steam] = steam;
        if(strcmp(ip, " ") == 1) data[us_ip] = ip;
        if(strcmp(password, " ") == 1) {
                data[us_password] = password;
        }
        if(user_id > 0) data[us_user_id] = user_id;
        if(authfail != AFAIL_NULL) data[us_authfail] = _:authfail;
        if(authflags != AFLAG_NULL) data[us_authflags] = _:authflags;
        if(accessflags != -1) data[us_accessflags] = accessflags;
        
        cache_string(data[us_password], sault_cache);
        
        database_modify_user(user_id, data);
}

public native__get_playerinfo(p_id, data[UserStruct]) {
        data = players_cache[p_id];
}

public native__set_playerinfo(p_id, 
                       username[NICK_LENGTH], 
                       steam[STEAM_LENGTH], 
                       ip[IP_LENGTH], 
                       password[CACHE_LENGTH], 
                       AuthFailActions:authfail, AuthFlags:authflags, accessflags, 
                       data[UserStruct]) {
        // Парсим данные в структуру data
        if(strcmp(username, " ") == 1) data[us_nickname] = username;
        if(strcmp(steam, " ") == 1) data[us_steam] = steam;
        if(strcmp(ip, " ") == 1) data[us_ip] = ip;
        if(strcmp(password, " ") == 1) {
                data[us_password] = password;
        }
        if(data[us_user_id] > 0) players_cache[p_id][us_user_id] = data[us_user_id];
        if(authfail != AFAIL_NULL) data[us_authfail] = _:authfail;
        if(authflags != AFLAG_NULL) data[us_authflags] = _:authflags;
        if(accessflags != -1) data[us_accessflags] = accessflags;
        
        cache_string(data[us_password], sault_cache);
        
        players_cache[p_id] = data;
}

public native__flush_playerinfo(p_id) {
        database_modify_user(players_cache[p_id][us_user_id], players_cache[p_id]);
}

public native__forcelogin(p_id, user_id, skip_checks) {
        auth_getuser(.user_id=user_id, .data = players_cache[p_id]);
        if(!skip_checks)
                authorize_client(p_id);
}

public native__forcelogout(p_id) {
        if(auth_player_status(p_id) && AUTH_SUCCESS) 
                unauthorize_client(p_id);
}

/*========================================= События ========================================*/
public client_putinserver(p_id) {
	    authorize_client(p_id);
}

public client_disconnected(p_id) {
	    unauthorize_client(p_id);
}

/*================================== Процедуры авторизации =================================*/

parse_client_data(p_id) {
        new user[UserStruct] = user_proto_default;
        players_cache[p_id] = user;
        get_user_name(p_id, players_cache[p_id][us_nickname], NICK_LENGTH); 
        get_user_authid(p_id, players_cache[p_id][us_steam], STEAM_LENGTH);
        get_user_ip(p_id, players_cache[p_id][us_ip], IP_LENGTH, true);
        get_user_info(p_id, pass_key, players_cache[p_id][us_password], CACHE_LENGTH);
        
        cache_passwd(p_id);
        players_cache[p_id][us_authstatus] = _:AUTH_EMPTY;
}

authorize_client(p_id, skip_reg = false) {
        static user[UserStruct]; 
        
        if(!is_user_connected(p_id)) 
                return;
        
        parse_client_data(p_id);        // Получаем данные игрока
        user = players_cache[p_id];     // Дублируем данные
        
        new info[2]; info[0] = p_id; info[1] = skip_reg;
        server_print("[AuthSystem] Searcing user");
        
        // Идентификация
        identify_mask(user, auth_flag);
        database_find_user(.data = user, .threaded = true, .callback = "database_identify", .extras = info, .size = 2);       // Получаем данные пользователя в БД
}

// процесс идентификации клиента, вызывается при асинхронном запросе
identify_client(p_id, user[UserStruct], skip_reg) {
        server_print("[AuthSystem] Indentify...");
        new bool: auth_success = true;
        static res;
        // Регистрация (пользователь не найден в БД)
        if(user[us_user_id] == 0 && !skip_reg) {
                server_print("[AuthSystem] Registering...");
                if(change_status(p_id, AUTH_NOT_REGISTERED) == AUTH_CONTINUE) {
                        database_create_user(players_cache[p_id]);
                        authorize_client(p_id, true);
                } 
        } else {

                // Аутентификация
                if(user[us_authflags] & AFLAG_NICK){
                        if(strcmp(players_cache[p_id][us_nickname], user[us_nickname])!=0)
                                auth_success = false;
                } else 
                if(user[us_authflags] & AFLAG_STEAM) {
                        if(strcmp(players_cache[p_id][us_steam], user[us_steam])!=0)
                                auth_success = false;
                } else
                if(user[us_authflags] & AFLAG_IP) {
                        if(strcmp(players_cache[p_id][us_ip], user[us_ip])!=0)
                                auth_success = false;
                } else
                if(user[us_authflags] & AFLAG_PASS) {
                        if(strcmp(players_cache[p_id][us_password], user[us_password])!=0)
                                auth_success = false;
                }
                else {
                        ExecuteForward(fwd_check, res, p_id, AUTH_SUCCESS, players_cache[p_id][us_authstatus], players_cache[p_id][us_user_id]);
                        if(res == AUTH_SUPERCEDE)
                                auth_success = false;
                }
        }

        if(auth_success) { // Авторизация успешна, меняем статус и отправляем его другим плагинам
                change_status(p_id, AUTH_SUCCESS);
                return;
        }
        else { // Авторизация не успешна, -//-
                change_status(p_id, AUTH_FAIL);
                return;
        }
}

unauthorize_client(p_id) {
        new user[UserStruct] = user_proto_default;

        players_cache[p_id] = user;
        if(is_user_connected(p_id)) change_status(p_id, AUTH_FAIL);

        change_status(p_id, AUTH_EMPTY);
}

cache_passwd(p_id) {
        new passwd[CACHE_LENGTH];
        copy(passwd, CACHE_LENGTH-1, players_cache[p_id][us_password]);
        
        cache_string(passwd, sault_cache);
        
        copy(players_cache[p_id][us_password], CACHE_LENGTH-1, passwd);
}

change_status(p_id, AuthStatus:status) {
        static res;
        
        if(status == players_cache[p_id][us_authstatus]) 
                return AUTH_CONTINUE;
        ExecuteForward(fwd_check, res, p_id, _:status, _:players_cache[p_id][us_authstatus], players_cache[p_id][us_user_id]);
	
	if(res == AUTH_SUPERCEDE) {
        	ExecuteForward(fwd_status_change, res, p_id, status, players_cache[p_id][us_authstatus], players_cache[p_id][us_user_id]);
                players_cache[p_id][us_authstatus] = _:status;
        }
        
        return res;
}

/*================================== Прочие методы плагина =================================*/

// Спецзаказ: выдержанная в соли кешированная строка
cache_string(text[], const sault[]) {
        static string[CACHE_LENGTH]; copy(string, CACHE_LENGTH-1, text);
        static buffer[CACHE_LENGTH+2]; 
        formatex(buffer, CACHE_LENGTH+2, "%s%s", text, sault);
        static cached_string[CACHE_LENGTH];
        
        hash_string(buffer, Hash_Sha3_256, cached_string, CACHE_LENGTH-1);
        
        copy(text, CACHE_LENGTH-1, cached_string);
}

stock dump_userinfo(data[UserStruct], message[] = "") {
        server_print("Dumping user data %s", message);
        server_print("> user_id:     %d", data[us_user_id]);
        server_print("> nickname:    %s", data[us_nickname]);
        server_print("> steam:       %s", data[us_steam]);
        server_print("> ip:          %s", data[us_ip]);
        server_print("> password:    %s", data[us_password]);
        server_print("> authfail:    %d", data[us_authfail]);
        server_print("> authflags:   %d", data[us_authflags]);
        server_print("> authstatus:  %d", data[us_authstatus]);
        server_print("> accessflags: %d", data[us_accessflags]);
}

identify_mask(user[UserStruct], AuthFlags:auth_mask) {
        static defaults[UserStruct] = user_proto_default;
        
        if(auth_mask & ~AFLAG_NICK) 
                copy(user[us_nickname], NICK_LENGTH, defaults[us_nickname]);
        if(auth_mask & ~AFLAG_STEAM) 
                copy(user[us_steam], STEAM_LENGTH, defaults[us_steam]);
        if(auth_mask & ~AFLAG_IP) 
                copy(user[us_ip], IP_LENGTH, defaults[us_ip]);
        if(auth_mask & ~AFLAG_PASS) 
                copy(user[us_password], CACHE_LENGTH, defaults[us_password]);
}

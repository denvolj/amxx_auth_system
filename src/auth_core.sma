/*============================================================================================
	
	---------------------------------
	-*- [ZL] Auth system core     -*-
	---------------------------------
	
	Система регистрации и авторизации.
	ToDo: 
	 - Возможность последовательного и параллельного обращения к БД
	 - Возможность работы с несколькими записями БД (результат оборачивать в array)
	 - Параллельное обращение реализовывать через последний строковый аргумент.
	   При отсутствии оного - использовать последовательную обработку.
	 - Для действий с отсутствующими пользователями (например регистрация пользователя, 
	   которого нет на сервере) использовать "виртуального" игрока с индексом 0.
============================================================================================*/

#pragma semicolon 1;

#include <amxmodx>
#include <auth_core>
#include <auth/database/mysql>


/*===================================== Блок констант ======================================*/
#define PLUG_OBJNAME			"AuthSystemCore"
#define PLUG_VERSION			"1.1.0"
#define PLUG_CREATOR			"Boec[SpecOPs]"


/*==================================== Блок переменных =====================================*/
new fwd_check, fwd_status_change;               // Форварды
new players_cache[33][UserStruct];              // Кеш пользователей

new retry_timer_offset = 0xFEAC2421;
new auth_flag;                                  // Флаг идентификации
new pass_key[5] = "_pw";                        // Поле пароля из user info
new sault_cache[CACHE_LENGTH];                  // Соль безопасности для хеширования

new cvar_authflag, cvar_sault;

/*================== Первичная инициализация и завершение работы плагина ===================*/

public plugin_init() {
	register_plugin(PLUG_OBJNAME, PLUG_VERSION, PLUG_CREATOR);
	
	// Регистрация forward-функций
	fwd_check         = CreateMultiForward("auth_check", ET_IGNORE, FP_CELL, FP_CELL, FP_CELL, FP_CELL);
	fwd_status_change = CreateMultiForward("auth_status_change", ET_IGNORE, FP_CELL, FP_CELL, FP_CELL, FP_CELL);
	
	// Регистрация cvar'ов
	cvar_authflag = register_cvar("auth_identify_by", "a");
	cvar_sault    = register_cvar("auth_security_sault", "229a51b0b6d67a8b079248b260064c89a7050ea334ed695399815e76f6f9f5a2");
	
	storage_init();
}

public plugin_cfg() {
	new flags[4];
	
	// Читаем квары
	get_pcvar_string(cvar_sault, sault_cache, CACHE_LENGTH-1);
        get_pcvar_string(cvar_authflag, flags, 3);
        
        // Покупаем соль для хеширования
	cache_string(sault_cache, sault_cache);
	
	// Устанавливаем поля для идентификации пользователя
	auth_flag = read_flags(flags);
}

public plugin_natives() {
	register_native("auth_player_status",   "native__status");
	register_native("auth_get_byplayer",    "native__get_byplayer");
	register_native("auth_adduser",         "native__adduser");
	register_native("auth_getuser",         "native__getuser");
	register_native("auth_deluser",         "native__deluser");
	register_native("auth_usermod",         "native__usermod");
	register_native("auth_get_playerinfo",  "native__get_playerinfo");
	register_native("auth_set_playerinfo",  "native__set_playerinfo");
	register_native("auth_flush_playerinfo","native__flush_playerinfo");
	register_native("auth_force_login",     "native__forcelogin");
	register_native("auth_force_logout",    "native__forcelogout");
}

/*===================================== Нативы плагина =====================================*/


/**
* Метод возвращает статус игрока (см. AuthStatus)
* @Param playerID - номер игрока на сервере
* @return AuthStatus - статус авторизации игрока
*/
public native__status(pluginID, args) {
        // аргументы метода
        static p_id;
        
        // получение аргументов
        p_id = get_param_byref(1);
        
        return players_cache[p_id][us_authstatus];
}


/**
* Метод возвращает ID зарегистрированного игрока по его номеру
* @Param playerID - номер игрока на сервере
* @return user_id - номер зарегистрированного пользователя. 0 - пользователь не найден/не авторизован
*/
public native__get_byplayer(pluginID, args) {
        // аргументы метода
        static p_id;
        
        // получение аргументов
        p_id = get_param_byref(1);
        
        if(players_cache[p_id][us_authstatus] != AUTH_SUCCESS) 
                return 0;
        
        return players_cache[p_id][us_user_id];
}


/**
* Метод регистрирует нового пользователя с помощью передачи пар ключ-значение (См. UserStruct)
* @Param UserStruct:api_key; - ключ
* @Param any:value;          - значение
* @OptParam [...];           - последовательность пар ключ-значение
* @OptParam callback[];      - имя функции для обратного вызова и возврата результата
* @return user_id            - номер пользователя в БД. 0 - в случае неудачи
*
* @callback(user_id);        - функция, имя которой передано для обратного вызова и её параметры
*
* @usage auth_adduser(api_key, value[, api_key, value[...], callback[] = ""]);
* @usage auth_adduser(UserStruct, user);
* @usage auth_adduser(us_nickname, "YoNickName", us_password, "YoPassword");
*/
public native__adduser(pluginID, args) {
        new user[UserStruct] = user_proto;              // Запись пользователя
        new thread_info[ThreadData] = thread_proto;     // Настройки поточного обращения к БД
        
        // Парсим аргументы натива
        parse_native_arguments(pluginID, args, user, thread_info);
        
        // Кешируем строку пароля
        cache_string(user[us_password], sault_cache);
        
        // Возвращаем либо -1 в случае потокового вызова, либо номер пользователя
        return storage_create_user(user, thread_info);
}


/**
* Метод получает данные пользователя(-лей) по парам ключ-значение
* @Param UserStruct:api_key; - ключ
* @Param any:value;          - значение
* @OptParam[...];            - последовательность пар ключ-значение
* @OptParam callback[];      - имя функции для обратного вызова и возврата результата
* @return Handle:array       - массив найденных пользователей по заданным ключам
*
* @callback(Handle:array);   - функция обратного вызова, будет передан параметр Handle с результатами
*/
public any:native__getuser(pluginID, args) {
        new user[UserStruct] = user_proto;              // Запись пользователя для поиска
        new thread_info[ThreadData] = thread_proto;     // Настройки поточного обращения к БД
        
        // Парсим аргументы натива
        parse_native_arguments(pluginID, args, user, thread_info);
        
        // Возвращаем либо -1 в случае потокового вызова, либо Handle массива с результатами
        return storage_find_user(user, thread_info);
}


/**
* Метод удаляет пользователя(-лей) из БД по заданным данным
* @Param UserStruct:api_key; - ключ
* @Param any:value;          - значение
* @OptParam[...];            - последовательность пар ключ-значение
* @OptParam callback[];      - имя функции для обратного вызова и возврата результата
* @return count              - количество затронутых записей
*
* @callback(count);          - функция обратного вызова, будет передан параметр с количеством затронутых записей
*/
public native__deluser(pluginID, args) {
        new user[UserStruct] = user_proto;              // Запись пользователя для поиска
        new thread_info[ThreadData] = thread_proto;     // Настройки поточного обращения к БД
        
        // Парсим аргументы натива
        parse_native_arguments(pluginID, args, user, thread_info);
        
        // Возвращаем либо -1 в случае потокового вызова, либо количество удалёных записей
        return storage_delete_user(user, thread_info);
}


/**
* Метод изменяет пользователя с номером user_id по заданным ключам
* Метод удаляет пользователя из БД
* @Param user_id             - номер пользователя в БД
* @Param UserStruct:api_key; - ключ
* @Param any:value;          - значение
* @OptParam[...];            - последовательность пар ключ-значение
* @OptParam callback[];      - имя функции для обратного вызова и возврата результата
* @return bool:result        - результат выполнения операции
*
* @callback(bool:result);    - функция обратного вызова, будет передан параметр с результатом выполнения операции
*/
public native__usermod(pluginID, args) {
        new user[UserStruct] = user_proto;              // Запись пользователя 
        new thread_info[ThreadData] = thread_proto;     // Настройки поточного обращения к БД
        new user_id = get_param_byref(1);
        
        // Парсим аргументы натива
        parse_native_arguments(pluginID, args, user, thread_info, 1);
        
        storage_modify_user(user_id, user, thread_info);
}


/**
* Метод получает кешированную информацию о пользователе
* @Param player_id           - номер игрока на сервере
* @Param user[UserStruct]    - структура, в которую будет записана информация о пользователе
*/
public native__get_playerinfo(pluginID, args) {
        // аргументы метода
        static p_id;
        
        // получение аргументов
        p_id = get_param_byref(1);
        
        set_array(2, players_cache[p_id], UserStruct);
}


/**
* Метод задаёт кешированную информацию о пользователе
* @Param player_id           - номер игрока на сервере
* @Param user[UserStruct]    - структура, которая будет записана
*/
public native__set_playerinfo(pluginID, args) {
        new thread_info[ThreadData] = thread_proto;     // Настройки поточного обращения к БД
        new p_id = get_param_byref(1);
        
        // Парсим аргументы натива
        parse_native_arguments(pluginID, args, players_cache[p_id], thread_info, 1);
        
        cache_string(players_cache[p_id][us_password], sault_cache);
}


/**
* Метод заносит информацию о пользователе в базу данных
* @Param p_id           - номер игрока на сервере
*/
public native__flush_playerinfo(pluginID, args) {
        new p_id = get_param_byref(1);
        storage_modify_user(players_cache[p_id][us_user_id], players_cache[p_id]);
}


/**
* Метод позволяет форсировать авторизацию игрока
* @Param player_id - номер игрока на сервере
* @Param user_id - номер зарегистрированного игрока
* @Param skip_checks - пропускать проверки подлинности
*/
public native__forcelogin(pluginID, args) {
        
        // аргументы метода
        static p_id, user_id, skip_checks;
        
        // получение аргументов
        p_id = get_param_byref(1);
        user_id = get_param_byref(2);
        skip_checks = get_param_byref(3);

        if(skip_checks)
                auth_getuser(AUTH_EXTRA, p_id, us_user_id, user_id, "identify_client");
}


/**
* Метод позволяет форсировать выход игрока
* @Param player_id - номер игрока на сервере
*/
public native__forcelogout(pluginID, args) {
        static p_id;
        p_id = get_param_byref(1);
        if(players_cache[p_id][us_authstatus] && AUTH_SUCCESS) 
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

// Записывает данные игрока в его кеш
parse_client_data(p_id) {
        new user[UserStruct] = user_proto;
        players_cache[p_id] = user;
        get_user_name(p_id, players_cache[p_id][us_nickname], NICK_LENGTH); 
        get_user_authid(p_id, players_cache[p_id][us_steam], STEAM_LENGTH);
        get_user_ip(p_id, players_cache[p_id][us_ip], IP_LENGTH, true);
        get_user_info(p_id, pass_key, players_cache[p_id][us_password], CACHE_LENGTH);
        
        cache_passwd(p_id);
        players_cache[p_id][us_authstatus] = _:AUTH_EMPTY;
}

// Периодическая авторизация, если пользователь всё ещё регистрируется
public authorize_client_task(t_id) {
        authorize_client(t_id - retry_timer_offset);
}

// Поддельный вход
public authorize_client_fake(Array:handle, p_id) {
        change_status(p_id, AUTH_SUCCESS);
        static user[UserStruct];
        
        array_read_user(handle, user);
        ArrayDestroy(handle);
        players_cache[p_id] = user;
}

// Процедура регистрации нового пользователя
public register_client(p_id) {
        // Если пользователь не идентифицирован и не проходит регистрацию
        // то задать статус регистрации, добавить в БД запись пользователя
        if(players_cache[p_id][us_authstatus] != AUTH_NOT_REGISTERED
        && change_status(p_id, AUTH_NOT_REGISTERED) == AUTH_CONTINUE) {
                auth_adduser(UserStruct, players_cache[p_id], "");
        } 
        
        // Установить задержку перед следующей авторизацией
        set_task(3.0, "authorize_client_task", retry_timer_offset+p_id);
}

// Старт процедуры авторизации
authorize_client(p_id) {
        static user[UserStruct];
        
        if(!is_user_connected(p_id)) 
                return;
        
        parse_client_data(p_id);        // Получаем данные игрока
        user = players_cache[p_id];     // Дублируем данные
        
        server_print("[AuthSystem] Searching user");
        identify_mask(user, auth_flag);
        auth_getuser(AUTH_EXTRA, p_id, UserStruct, user, "identify_client");
}

// Идентификация клиента
public identify_client(Array:handle, p_id) {
        static user[UserStruct];
        array_read_user(handle, user);
        
        ArrayDestroy(handle);
        authenticate_client(user, p_id);
}

// процесс аутентификация клиента, вызывается при асинхронном запросе
public authenticate_client(user[UserStruct], p_id) {
        server_print("[AuthSystem] Indentify...");
        new bool: auth_success = true;
        static res;
        // Пользователя нет в БД, регистрируем его с последующей переавторизацией
        if(user[us_user_id] == 0) {
                server_print("[AuthSystem] Registering...");
                
                register_client(p_id);
                return;
                
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

        // Проверки пройдены,
        // Плагины разрешили пользователю пройти авторизацию
        // Сохраняем пользователю структуру и выдаем его номер
        if(change_status(p_id, AUTH_SUCCESS) == AUTH_CONTINUE && auth_success) { 
                players_cache[p_id] = user;
                server_print("[AuthSystem] %d :: %s has logged in.", players_cache[p_id][us_user_id], players_cache[p_id][us_nickname]);
                
                return;
        }
        // Авторизация не успешна или плагины заблокировали авторизацию
        // Меняем статус игроку как провалившему проверку
        else { 
                change_status(p_id, AUTH_FAIL);
                return;
        }
}

unauthorize_client(p_id) {
        new user[UserStruct] = user_proto;

        players_cache[p_id] = user;
        if(is_user_connected(p_id)) 
                change_status(p_id, AUTH_FAIL);
        else
                change_status(p_id, AUTH_EMPTY);
}

cache_passwd(p_id) {
        new passwd[CACHE_LENGTH];
        copy(passwd, CACHE_LENGTH-1, players_cache[p_id][us_password]);
        
        cache_string(passwd, sault_cache);
        
        copy(players_cache[p_id][us_password], CACHE_LENGTH-1, passwd);
}

change_status(p_id, status) {
        static res;
        static user_id;
        if(players_cache[p_id][us_user_id])
                user_id = players_cache[p_id][us_user_id];
        else
                user_id = 0;
        
        if(status == players_cache[p_id][us_authstatus]) 
                return AUTH_CONTINUE;
        ExecuteForward(fwd_check, res, p_id, status, players_cache[p_id][us_authstatus], user_id);
	
	// Плагины отправили AUTH_CONTINUE, разрешив работу форварда
	if(res == AUTH_CONTINUE) {
        	ExecuteForward(fwd_status_change, res, p_id, status, players_cache[p_id][us_authstatus], user_id);
                players_cache[p_id][us_authstatus] = status;
        }
        
        return res;
}

/*================================== Прочие методы плагина =================================*/


// Организуем получение аргументов по паре "ключ-значение"
parse_native_arguments(pluginID, args, user[UserStruct], thread_info[ThreadData], param = 0) {
        // Т.к. user и thread_info - массивы, а массивы передаются через указатели,
        // то если мы изменим значения здесь, то они изменятся и в месте, откуда вызван парсер
        // Это позволит держать код DRY.
        static property, callback[64];
        
        do {
                property = get_param_byref(++param);

                switch(property) {
                        case UserStruct: get_array(++param, user, UserStruct-1);
                        case us_nickname: get_string(++param, user[us_nickname], NICK_LENGTH-1);
                        case us_steam: get_string(++param, user[us_steam], STEAM_LENGTH-1);
                        case us_ip: get_string(++param, user[us_ip], IP_LENGTH-1);
                        case us_password: get_string(++param, user[us_password], CACHE_LENGTH-1);
                        case us_authfail, us_authflags, us_accessflags: {
                                user[property] = get_param_byref(++param);
                        }
                        case AUTH_EXTRA: {
                                thread_info[TDInfoFlags] = get_param_byref(++param);
                        }
                }
                
                // Если остался последний параметр, то это метод обратного вызова
                // Подготавливаем данные для поточного обращения к БД
                if(param+1 == args) {
                        get_string(++param, callback, 63);
                        thread_info[TDFunction] = get_func_id(callback, pluginID);
                        
                        // При пустой строке просто выполняем запрос к БД в отдельном потоке
                        if(equal(callback, "")) {
                                thread_info[useThread] = true;
                                return;
                        }
                        
                        // Функция была найдена в вызывающем плагине;
                        // Задаём параметры обратного вызова
                        if(thread_info[TDFunction] >= 0) {
                                thread_info[TDPlugin] = pluginID;
                                thread_info[useThread] = true;
                        } else {
                                // Кидаем предупреждение, что метод не найден
                                server_print("[AuthSystem] Warning: Callback not found.");
                        }
                }
                        
        } while (param <= args);
        return;
}

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

identify_mask(user[UserStruct], auth_mask) {
        static defaults[UserStruct] = user_proto;
        
        if(auth_mask & ~AFLAG_NICK) 
                copy(user[us_nickname], NICK_LENGTH, defaults[us_nickname]);
        if(auth_mask & ~AFLAG_STEAM) 
                copy(user[us_steam], STEAM_LENGTH, defaults[us_steam]);
        if(auth_mask & ~AFLAG_IP) 
                copy(user[us_ip], IP_LENGTH, defaults[us_ip]);
        if(auth_mask & ~AFLAG_PASS) 
                copy(user[us_password], CACHE_LENGTH, defaults[us_password]);
}

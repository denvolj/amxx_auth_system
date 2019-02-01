
#if defined _authorization_included
    #endinput
#endif
#define _authorization_included

// Блок констант
#define PASSWORD_HASH_LENGTH 256


// Результат работы форварда - для определения дальнейшей обработки события
enum {
    AUTH_EXTRA = -1,        // Зарезервировано для обращения к БД
    AUTH_CONTINUE = 0,      // Продолжить работу форварда в штатном положении
    AUTH_SUPERCEDE          // Прервать работу форварда
};

// Статус авторизации игрока
enum _:AuthStatus {
    AUTH_NULL = 0,          // Значение не задано/пустой слот
    AUTH_NOT_REGISTERED = 1,// Пользователь не зарегистрирован
    AUTH_SUCCESS,           // Пользователь авторизован
    AUTH_FAIL,              // Пользователь не авторизован
    AUTH_EMPTY              // Пользователь в процессе авторизации
};

// Флаги авторизации (по каким полям проверять авторизацию пользователя)
enum _:AuthFlags (<<=1) {
    AFLAG_NULL = 0,    // Значение не задано
    AFLAG_NICK = 1,    // По нику (a)
    AFLAG_STEAM,       // SteamID (b)
    AFLAG_IP,      // IP адресу (c)
    AFLAG_PASS     // Паролю (d)
};

// Действия при ошибке авторизации
enum _:AuthFailActions(<<=1) {
    AFAIL_NULL = 0,
    AFAIL_KICK = 1,  // Кикнуть игрока
    AFAIL_BAN,       // Забанить игрока
    AFAIL_LOG    // Занести действие в лог
}

// Это так же API ключи для взаимодействия плагинов через auth_get_info/auth_set_info
// Структура, в которой хранится вся необходимая информация об игроке
enum _:UserStruct {
    us_user_id,             // ID зарегистрированного пользователя
    us_nickname[MAX_NAME_LENGTH],       // Имя пользователя
    us_steam[MAX_AUTHID_LENGTH],     // SteamID
    us_ip[MAX_IP_LENGTH],           // IP адрес
    us_password[PASSWORD_HASH_LENGTH],      // Пароль
    us_authfail,            // Действия при ошибке авторизации
    us_authflags,           // Правила аутентификации пользователя
    us_authstatus,          // Статус авторизации
    us_accessflags          // Права доступа игрока
} 
#define user_proto { 0, "", "", "", "", AFAIL_NULL, AFLAG_NULL, AUTH_EMPTY, 0}


// Структура для определения поточного запроса к БД
enum _:ThreadData {
    bool:useThread,         // Использовать поточный вызов?
    TDPlugin,               // Плагин, инициировавший запрос
    TDFunction,             // Функция обратного вызова в этом плагине
    TDInfoFlags             // Дополнительные параметры/флаги запроса
} 
#define thread_proto {false, -1, -1, 0}

/**
* Метод возвращает статус игрока (см. AuthStatus)
* @Param playerID - номер игрока на сервере
* @return AuthStatus - статус авторизации игрока
*/
native AuthStatus:auth_player_status(player_id);

/**
* Метод возвращает ID зарегистрированного игрока по его номеру
* @Param playerID - номер игрока на сервере
* @return user_id - номер зарегистрированного пользователя. 0 - пользователь не найден/не авторизован
*/
native auth_get_byplayer(player_id);

/**
* Метод регистрирует нового пользователя с помощью передачи пар ключ-значение (См. UserStruct)
* @Param UserStruct:api_key; - ключ
* @Param any:value;      - значение
* @OptParam [...];       - последовательность пар ключ-значение
* @OptParam callback[];      - имя функции для обратного вызова и возврата результата
* @return user_id        - номер пользователя в БД. 0 - в случае неудачи
*
* @callback(user_id);    - функция, имя которой передано для обратного вызова и её параметры
*
* @usage auth_adduser(api_key, value[, api_key, value[...], callback[] = ""]);
* @usage auth_adduser(UserStruct, user);
* @usage auth_adduser(us_nickname, "YoNickName", us_password, "YoPassword");
*/
native auth_adduser(...);

/**
* Метод получает данные пользователя(-лей) по парам ключ-значение
* @Param UserStruct:api_key; - ключ
* @Param any:value;      - значение
* @OptParam[...];        - последовательность пар ключ-значение
* @OptParam callback[];      - имя функции для обратного вызова и возврата результата
* @return Handle:array       - массив найденных пользователей по заданным ключам
*
* @callback(Handle:array);   - функция обратного вызова, будет передан параметр Handle с результатами
*/
native any:auth_getuser(...);

/**
* Метод удаляет пользователя(-лей) из БД по заданным данным
* @Param UserStruct:api_key; - ключ
* @Param any:value;      - значение
* @OptParam[...];        - последовательность пар ключ-значение
* @OptParam callback[];      - имя функции для обратного вызова и возврата результата
* @return count          - количество затронутых записей
*
* @callback(count);      - функция обратного вызова, будет передан параметр с количеством затронутых записей
*/
native auth_deluser(...);

/**
* Метод изменяет пользователя с номером user_id по заданным ключам
* Метод удаляет пользователя из БД
* @Param user_id         - номер пользователя в БД
* @Param UserStruct:api_key; - ключ
* @Param any:value;      - значение
* @OptParam[...];        - последовательность пар ключ-значение
* @OptParam callback[];      - имя функции для обратного вызова и возврата результата
* @return bool:result    - результат выполнения операции
*
* @callback(bool:result);    - функция обратного вызова, будет передан параметр с результатом выполнения операции
*/
native auth_usermod(...);

/**
* Метод получает кешированную информацию о пользователе
* @Param player_id       - номер игрока на сервере
* @Param user[UserStruct]    - структура, в которую будет записана информация о пользователе
*/
native auth_get_playerinfo(...);

/**
* Метод задаёт кешированную информацию о пользователе
* @Param player_id       - номер игрока на сервере
* @Param user[UserStruct]    - структура, которая будет записана
*/
native auth_set_playerinfo(...);

/**
* Метод заносит информацию о пользователе в базу данных
* @Param player_id       - номер игрока на сервере
*/
native auth_flush_playerinfo(...);

/**
* Метод позволяет форсировать авторизацию игрока
* @Param player_id - номер игрока на сервере
* @Param user_id - номер зарегистрированного игрока
* @Param skip_checks - пропускать проверки подлинности
*/
native auth_force_login(...);

/**
* Метод позволяет форсировать выход игрока
* @Param player_id - номер игрока на сервере
*/
native auth_force_logout(...);

/**
* Метод вызывается перед сменой статуса
* @Param player_id - номер игрока
* @Param AuthStatus: new_status - новый статус
* @Param AuthStatus: old_status - старый статус
* @Param user_id - номер зарегистрированного пользователя (0 - если пользователь не был авторизован)
* @return AUTH_SUPERCEDE - какой-то плагин заблокировал смену статуса
*     AUTH_CONTINUE - продолжаем действие 
*/
forward auth_check(player_id, new_status, old_status, user_id);

/**
* Метод вызывается при смене статуса авторизации
* @Param player_id - номер подключающегося игрока
* @Param AuthStatus: new_status - новый статус
* @Param AuthStatus: old_status - старый статус
* @Param user_id - номер зарегистрированного пользователя (0 - если пользователь не был авторизован)
*/
forward auth_status_change(player_id, new_status, old_status, user_id);

stock auth_equal(const data[UserStruct], field, comparewith[UserStruct] = user_proto)
{
    switch(field)
    {
        case us_nickname, us_steam, us_password, us_ip:
            return (strcmp(data[field], comparewith[field])==0);
        case us_user_id, us_authfail, us_authflags, us_authstatus, us_accessflags:
            return (data[field] == comparewith[field]);
        
        default:
        {
            server_print("[stock AuthCore::auth_equal] Non-struct offsets used in comparison. Returning false.");
            return false;
        }
    }
    return false;
}

/* Метод для заполнения структуры
* @usage patch_struct(user, temp_user);
* @usage patch_struct(user, .user_id = 5, .nickname = "YoNickName", .accessflags = (1<<32));
*/
stock patch_struct(     
        dest[UserStruct], 
        const source[UserStruct] = user_proto,
        nickname[MAX_NAME_LENGTH] = "",
        steam[MAX_AUTHID_LENGTH] = "",
        ip[MAX_IP_LENGTH] = "",
        password[PASSWORD_HASH_LENGTH] = "",
        authflags = AFLAG_NULL,
        authfail = AFAIL_NULL,
        authstatus = AUTH_EMPTY,
        accessflags = 0) 
{
    // Сливаем переданную структуру (реализация копирования)
    copy(dest, UserStruct-1, source);
    
    // Сравниваем значения со значениями по умолчанию, не стандарт - сливаем в структуру
    if(user_id != user_proto[us_user_id])       dest[us_user_id]     = user_id;
    if(authflags != user_proto[us_authflags])       dest[us_authflags]   = authflags;
    if(authfail != user_proto[us_authfail])     dest[us_authfail]    = authfail;
    if(authstatus != user_proto[us_authstatus])     dest[us_authstatus]  = authstatus;
    if(accessflags != user_proto[us_accessflags])   dest[us_accessflags] = accessflags;
    
    // Строковые сравнения
    if(!equal(nickname, user_proto[us_nickname])) copy(dest[us_nickname], MAX_NAME_LENGTH-1);
    if(!equal(steam, user_proto[us_steam]))       copy(dest[us_steam], MAX_AUTHID_LENGTH-1);
    if(!equal(ip, user_proto[us_ip]))         copy(dest[us_ip], MAX_IP_LENGTH-1);
    if(!equal(password, user_proto[us_password])) copy(dest[us_password], PASSWORD_HASH_LENGTH-1);
}

// Хендл -1 обозначает, что мы используем предыдущий хендл. Индекс -1 обозначает, что мы действуем инкрементально.
stock array_read_user(user[UserStruct], Array:new_handle = -1, new_index = -1) {
    static Array:handle = -1, index = 0, size = 1;

    if(new_handle != -1) {
        handle = new_handle;
        index = 0;
    }


    if(new_index != -1) 
        index = new_index;

    if(any:handle <= 0)
        return false;

    size = ArraySize(handle);

    if (index >= size) 
        return false;

    ArrayGetArray(handle, index, user);
    
    index++; 
   
    return (index < size);
}
            
            
            


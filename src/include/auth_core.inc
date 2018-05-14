
#if defined _authorization_included
        #endinput
#endif
#define _authorization_included

// Блок констант
#define NICK_LENGTH 32
#define STEAM_LENGTH 32
#define IP_LENGTH 20
#define CACHE_LENGTH 70

#define user_proto { 0, " ", " ", " ", " ", AFAIL_NULL, AFLAG_NULL, AUTH_NULL, -1}
#define user_proto_default { 0, " ", " ", " ", " ", AFAIL_NULL, AFLAG_NULL, AUTH_EMPTY, 0}


// Результат работы форварда - для определения дальнейшей обработки события
enum {
        AUTH_CONTINUE = 0,
        AUTH_SUPERCEDE
};

// Статус авторизации игрока
enum AuthStatus {
        AUTH_NULL = 0,                  // Значение не задано
        AUTH_NOT_REGISTERED = 1,        // Пользователь не зарегистрирован
        AUTH_SUCCESS,                   // Пользователь авторизован
        AUTH_FAIL,                      // Пользователь не авторизован
        AUTH_EMPTY                      // Абонет не абонент (пустой слот)
};

// Флаги авторизации (по каким полям проверять авторизацию пользователя)
enum AuthFlags (<<=1) {
        AFLAG_NULL = 0,    // Значение не задано
        AFLAG_NICK = 1,    // По нику (a)
        AFLAG_STEAM,       // SteamID (b)
        AFLAG_IP,          // IP адресу (c)
        AFLAG_PASS         // Паролю (d)
};

// Действия при ошибке авторизации
enum AuthFailActions(<<=1) {
        AFAIL_NULL = 0,
        AFAIL_KICK = 1,  // Кикнуть игрока
        AFAIL_BAN,       // Забанить игрока
        AFAIL_LOG        // Занести действие в лог
}

// Это так же API ключи для взаимодействия плагинов через auth_get_info/auth_set_info
// Структура, в которой хранится вся необходимая информация об игроке
enum UserStruct {
        us_user_id,                     // ID зарегистрированного пользователя
        us_nickname[NICK_LENGTH],       // Имя пользователя
        us_steam[STEAM_LENGTH],         // SteamID
        us_ip[IP_LENGTH],               // IP адрес
        us_password[CACHE_LENGTH],      // Пароль
        AuthFailActions:us_authfail,    // Действия при ошибке авторизации
        AuthFlags:us_authflags,         // Правила аутентификации пользователя
        AuthStatus:us_authstatus,       // Статус авторизации
        us_accessflags                  // Права доступа игрока
} 


/**
* Метод возвращает статус игрока (см. AuthStatus)
* @param playerID - номер игрока на сервере
* @return AuthStatus - статус авторизации игрока
*/
native AuthStatus:auth_player_status(playerID);

/**
* Метод возвращает ID зарегистрированного игрока по его номеру
* @param playerID - номер игрока на сервере
* @return user_id - номер зарегистрированного пользователя. 0 - пользователь не найден/не авторизован
*/
native auth_get_byplayer(playerID);

/**
* Метод регистрирует нового пользователя
* @usage auth_adduser(.username="YoNick", .password="yoSecretPass");
* @usage auth_adduser(.steam="STEAM_1:0:012345", .ip="127.0.0.1", .authfail=AFAIL_KICK);
* @return user_id - номер зарегистрированного пользователя
*/
native auth_adduser(user_id=0, username[NICK_LENGTH]=" ", steam[STEAM_LENGTH]=" ", ip[IP_LENGTH]=" ", password[CACHE_LENGTH]=" ", authfail=0, authflags=0, accessflags=0, data[UserStruct] = user_proto);

/**
* Метод получает данные пользователя по ключу
* @usage auth_getuser(.username="YoNick", .password="yoSecretPass", .ret=yo_array);
* @usage auth_getuser(.steam="STEAM_1:0:012345",.ret=yo_array);
* @usage auth_getuser(.user_id=5,.ret=yo_array);
*/
native auth_getuser(user_id=0, username[NICK_LENGTH]=" ", steam[STEAM_LENGTH]=" ", ip[IP_LENGTH]=" ", password[CACHE_LENGTH]=" ", data[UserStruct] = user_proto);

/**
* Метод удаляет пользователя
* @param user_id - ID зарегистрированного пользователя
* @return bool:result - успешность выполнения операции
*/
native auth_deluser(user_id);

/**
* Метод изменяет пользователя
* @param user_id - ID зарегистрированного пользователя
* <...>
* @usage auth_adduser(.user_id=10, .steam="STEAM_1:0:012345", .ip="127.0.0.1", .authfail=AFAIL_KICK);
*/
native auth_usermod(user_id=0, username[NICK_LENGTH]=" ", steam[STEAM_LENGTH]=" ", ip[IP_LENGTH]=" ", password[CACHE_LENGTH]=" ", authfail=-1, authflags=-1, accessflags=-1, data[UserStruct] = user_proto);

/**
* Метод получает кешированную информацию о пользователе
* @param player_id - номер игрока на сервере
* @param user[UserStruct] - структура, в которую будет записана информация о пользователе
*/
native auth_get_playerinfo(player_id, ret[UserStruct]);

/**
* Метод задаёт кешированную информацию о пользователе
* @param player_id - номер игрока на сервере
* @param user[UserStruct] - структура, которая будет записана
*/
native auth_set_playerinfo(player_id, username[NICK_LENGTH]=" ", steam[STEAM_LENGTH]=" ", ip[IP_LENGTH]=" ", password[CACHE_LENGTH]=" ", authfail=-1, authflags=-1, accessflags=-1, data[UserStruct] = user_proto);

/**
* Метод заносит информацию о пользователе в базу данных
* @param player_id - номер игрока на сервере
*/
native auth_flush_playerinfo(player_id);

/**
* Метод позволяет форсировать авторизацию игрока
* @param player_id - номер игрока на сервере
* @param user_id - номер зарегистрированного игрока
* @param skip_checks - пропускать проверки подлинности
* @return bool: result - успешность операции
*/
native auth_force_login(player_id, user_id, skip_checks = true);

/**
* Метод позволяет форсировать выход игрока
* @param player_id - номер игрока на сервере
* @return bool: result - успешность операции
*/
native auth_force_logout(player_id);

/**
* Метод вызывается перед сменой статуса
* @param player_id - номер игрока
* @param AuthStatus: new_status - новый статус
* @param AuthStatus: old_status - старый статус
* @param user_id - номер зарегистрированного пользователя (0 - если пользователь не был авторизован)
* @return AUTH_SUPERCEDE - какой-то плагин заблокировал смену статуса
*         AUTH_CONTINUE - продолжаем действие 
*/
forward auth_check(player_id, new_status, old_status, user_id);

/**
* Метод вызывается при смене статуса авторизации
* @param player_id - номер подключающегося игрока
* @param AuthStatus: new_status - новый статус
* @param AuthStatus: old_status - старый статус
* @param user_id - номер зарегистрированного пользователя (0 - если пользователь не был авторизован)
*/
forward auth_status_change(player_id, new_status, old_status, user_id);

stock auth_equal(const data[UserStruct], UserStruct:field, comparewith[UserStruct] = user_proto_default)
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


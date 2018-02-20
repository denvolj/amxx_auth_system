/*===================================== Блок констант ======================================*/
#define ZL_DATABASE "ZombieLite"
#define ZL_TABLE_USERS "zl_auth_users"
#define ZL_INFO_PASS "zl_ac"

// Битовые флаги проверки полей записи (используется в authFlag)
const auth_uname		= (1<<1);
const auth_pass 		= (1<<2);
const auth_sID  		= (1<<3);
const auth_ip 			= (1<<4);

// Битовые флаги для выборки из таблицы
const zl_userID		= (1<<0);
const zl_userName	= (1<<1);
const zl_userPass	= (1<<2);
const zl_userSteam	= (1<<3);
const zl_userIP		= (1<<4);
const zl_userLevel	= (1<<5);
const zl_userFields = 31

// Внутренние стандарты
const NAME_MAXLEN 	= 128
const PASS_MAXLEN   = 64
const MD5_MAXLEN  	= 34
const IP_MAXLEN		= 23
const STEAMID_MAXLEN = 128

// Возврат состояния выполнения функции
enum _:authReturn
{
	acNULL = 0,
	acSuccess,
	acWarning,
	acError,
	acKernelPanic	// Необработанная ошибка плагина (исключительно для контрольного ядра)
};

// Статус пользователя
enum _:authStatus
{
	asNull = 0,			// Свободный слот
	asAuthorized,		// Пользователь авторизован
	asNotAuthorized,	// Пользователь не авторизован
	asNotRegistered		// Пользователь не зарегистрирован
};

enum _:authPropeties 
{
	ap_IP,
	ap_SID,
	ap_PASSWD
}

/*===================================== Блок структур ======================================*/
enum _:userRecord
{
	ur_uID,						// ID пользователя в системе
	ur_username[NAME_MAXLEN],	// Ник
	ur_password[MD5_MAXLEN],	// Пароль (md5)
	ur_steamID[STEAMID_MAXLEN],	// СтимИД
	ur_IP[IP_MAXLEN],			// Айпи адрес
	ur_level,
	ur_logStatus
};

/*===================================== Блок запросов ======================================*/

/* Список функций, необходимых к реализации:
- Добавление пользователя (sql)+
- Удаление пользователя по uID (sql)
- Получение uID по authFlag и необходимым данным
- Редактирование данных по uID (sql)
- Получение данных по uID (sql)
*/

/*===================================== Блок natives  ======================================*/

native zl_auth_adduser(...);
native zl_auth_setuser(...);
native zl_auth_deluser(...);
native zl_auth_getuser(...);
native zl_auth_getuser_by_pid(playerID);
native zl_auth_cached_get(...);
native zl_auth_cached_set(...);

/*====================================== Блок стоков =======================================*/

stock getPrototype() {
	new user[userRecord];
	user[ur_username] 	= "";
	user[ur_IP] 		= "";
	user[ur_steamID]	= "";
	user[ur_password]	= "";
	user[ur_level]		= 1;
	
	return user;
}

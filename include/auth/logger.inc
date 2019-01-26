
#if defined _gamex_plugin_debugger_included
  #endinput
#endif
#define _gamex_plugin_debugger_included

/*
 * This file stores all debug methods and information
 *
*/

enum _:SMessageMode (<<=1) {
    smm_info = 1,
    smm_verb,
    smm_debug,
    smm_warn,
    smm_error,
    smm_exception,
    smm_fail
}; 

new __loglevel = smm_error | smm_exception | smm_fail | smm_info | smm_verb | smm_warn | smm_debug;

enum _:SMessage {
    sm_code,
    sm_type,
    sm_description[128]
};

enum _:SMessageCodes {
    MESSAGE_OK = 0,
    INFO_PLUGIN_INIT,
    INFO_PLUGIN_CFG,
    INFO_CLIENT_AUTH,
    INFO_CLIENT_REGISTER,
    INFO_CLIENT_FORCE_AUTH,
    INFO_CLIENT_REGAUTH,
    INFO_CLIENT_LOGIN,
    INFO_STATUS_CHANGE,
    INFO_PARSING_CLIENT,
    DEBUG_EVENT_TRIGGERED,
    DEBUG_NATIVE_CALL,
    DEBUG_PARAM_STRING,
    DEBUG_PARAM_INT,
    DEBUG_PARAM_FLOAT,
    DEBUG_SQL,
    ERROR_CALLBACK_NOT_FOUND
};

new const MESSAGE_TABLE[SMessageCodes][SMessage] = {
    {MESSAGE_OK,                    smm_info,       "All OK. No errors >:3"},
    {INFO_PLUGIN_INIT,              smm_info,       "Plugin initialization..."},
    {INFO_PLUGIN_CFG,               smm_info,       "Loading configuration..."},
    {INFO_CLIENT_AUTH,              smm_info,       "Authorizing client..."},
    {INFO_CLIENT_REGISTER,          smm_info,       "Registering client..."},
    {INFO_CLIENT_FORCE_AUTH,        smm_info,       "Force auth client..."},
    {INFO_CLIENT_REGAUTH,           smm_info,       "Forcing auth after registration..."},
    {INFO_CLIENT_LOGIN,             smm_info,       "%d :: %s has logged in."},
    {INFO_STATUS_CHANGE, smm_verb | smm_info,       "Status change: %d > %d"},
    {INFO_PARSING_CLIENT,smm_verb | smm_info,       "Parsing client data..."},
    {DEBUG_EVENT_TRIGGERED,         smm_debug,      "Event %s(...)"},
    {DEBUG_NATIVE_CALL,             smm_debug,      "Native call %s(...) (caller id: %d)"},
    {DEBUG_PARAM_STRING, smm_verb | smm_debug,      "> (str) %s"},
    {DEBUG_PARAM_INT,    smm_verb | smm_debug,      "> (int) %d"},
    {DEBUG_PARAM_FLOAT,  smm_verb | smm_debug,      "> (float) %f"},
    {DEBUG_SQL,                     smm_debug,      "SQL: %s"},
    {ERROR_CALLBACK_NOT_FOUND,      smm_error,      "Error! Callback %d::%s(...) not found"},
};

stock get_plugin_name()
{
    static name[24], isset=false;
    if(!isset) {
        get_plugin(-1, .name = name, .len2 = charsmax(name));
        isset = true;
    }
    return name;
}

stock logger(message_code, any:...) 
{
    new message[256], msg_format[128];
    copy(msg_format, charsmax(msg_format), MESSAGE_TABLE[message_code][sm_description]);
    vformat(message, charsmax(message), msg_format, 2);
    format(message, charsmax(message), "[%s] %s", get_plugin_name(), message);

    switch(MESSAGE_TABLE[message_code][sm_type]) {
        case smm_error: {
            log_error(message_code, message);
        }
        case smm_exception: {
            abort(MESSAGE_TABLE[message_code][sm_code], message);
        }
        case smm_fail: {
            set_fail_state(message);
        }
        default: {
            if(!(MESSAGE_TABLE[message_code][sm_type] & __loglevel)) {
                return;
            }
            server_print(message);
        }
    }
    return;
}

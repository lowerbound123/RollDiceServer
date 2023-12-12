//
// Created by Tony Chow on 2023/12/1.
//

#ifndef ROLLDICE_USERMANAGER_H
#define ROLLDICE_USERMANAGER_H

#include "pqxx/pqxx"
#include "dicedb.h"
#include "json.hpp"
#include "string"

namespace UserManager {
    nlohmann::json addUser(Dicedb::PgDB db, nlohmann::json data);

    nlohmann::json validateUser(Dicedb::PgDB db, nlohmann::json data);

    nlohmann::json checkToken(Dicedb::PgDB db, nlohmann::json data);

    std::string getCookie(Dicedb::PgDB db, std::string id);
}

#endif //ROLLDICE_USERMANAGER_H

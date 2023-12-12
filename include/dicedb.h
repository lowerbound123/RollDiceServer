//
// Created by Tony Chow on 2023/11/28.
//
#ifndef ROLLDICE_DICEDB_H
#define ROLLDICE_DICEDB_H

#include "string"
#include "pqxx/pqxx"
#include "vector"
#include "json.hpp"
#include "basic_class.h"

namespace Dicedb {
    class PgDB {
    private:
        pqxx::connection *db;
        std::string array2json(std::string) const;
    public:
        PgDB() = default;

        std::string get_current_time();

        bool connect(std::string query);

        bool connect(std::string dbname,
                     std::string username,
                     std::string password);

        void close();

        int updateTime(std::string username);

        int insertUser(std::string username,
                       std::string nickname,
                       std::string password,
                       std::string email = "",
                       std::string qq = "",
                       std::string wechat = "");

        int checkPassword(std::string username,
                          std::string password);

        int askKeyWithName(std::string username, std::string &key);

        int askKeyWithId(std::string id, std::string &key);

        int queryUsers(std::string itemName, std::string conditionName, std::string conditionValue, std::string &ans);

        int askId(std::string username, std::string &id);

        nlohmann::json getOccupationList(std::string schema) const;

        int selectRoles(std::string username, std::vector<int> &ids);

        int getSkillList(std::string schema, std::vector<Skill> &skills) const;

        int insertRole(nlohmann::json data, std::string rule, int userId) const;

        int roleList(int userId, std::string ord, int limit, int offset, nlohmann::json &output) const;

        int queryRole(int roleId, int userId, std::string schema, nlohmann::json &output) const;
    };
}

#endif //ROLLDICE_DICEDB_H

//
// Created by Tony Chow on 2023/11/28.
//

#include "dicedb.h"
#include "iostream"
#include "pqxx/pqxx"
#include "crypto++/sha.h"
#include "crypto++/hex.h"
#include "crypto++/osrng.h"
#include "crypto++/aes.h"
#include <crypto++/filters.h>
#include "accessToken.h"
#include "basic_class.h"
#include "crypto++/base64.h"
#include "iomanip"
#include "chrono"
#include "sstream"
#include "cstdio"

using std::endl, std::cout;

namespace Dicedb {
    std::string PgDB::array2json(std::string x) const {
        x[0] = '[';
        x[x.size() - 1] = ']';
        return x;
    }

    std::string PgDB::get_current_time() {
        pqxx::work txn(*db);
        pqxx::result result = txn.exec("SELECT CURRENT_TIMESTAMP");
        return result[0][0].as<std::string>();
    }

    bool PgDB::connect(std::string query) {
        db = new pqxx::connection(query);

        if (db->is_open()) {
            std::cout << "Connection to database succeed." << std::endl;
            return true;
        }
        std::cout << "Fail to open database." << std::endl;
        return false;
    }

    bool PgDB::connect(std::string dbname,
                       std::string username,
                       std::string password) {
        std::string connection_string = "dbname=" + dbname + " user=" + username + " password=" + password;
        db = new pqxx::connection(connection_string);

        if (db->is_open()) {
            std::cout << "Connection to database succeed." << std::endl;
            return true;
        }
        std::cout << "Fail to open database." << std::endl;
        return false;
    }

    int PgDB::updateTime(std::string username) {
        try {
            pqxx::work txn(*db);
            std::string query = "UPDATE users SET last_login = current_timestamp WHERE username = $1";
            txn.exec_params(query, username);
            txn.commit();
        } catch (const std::exception e) {
            std::cout << "用户 " << username << " 的 login_time 更新失败" << std::endl;
            return 1;
        }
        return 0;
    }

    int PgDB::insertUser(std::string username,
                         std::string nickname,
                         std::string password,
                         std::string email,
                         std::string qq,
                         std::string wechat) {
        pqxx::work txn(*db);
        pqxx::result result = txn.exec("select count(*) as cnt from users where username = \'" + username + "\'");
        if (result[0]["cnt"].as<int>() != 0) return 1;
        txn.commit();

        // 将用户的密码进行SHA256
        CryptoPP::SHA256 hash;
        std::string hashedPassword;
        CryptoPP::StringSource(password, true,
                               new CryptoPP::HashFilter(hash,
                                                        new CryptoPP::HexEncoder(
                                                                new CryptoPP::StringSink(hashedPassword), false
                                                        )
                               )
        );

        // 生成一个随机的key，用来给accessToken加密和解密
        std::string keyHex = AccessToken::generateKey();

        std::string insert = "INSERT INTO public.users " \
                             "(username, nickname, password_sha, key, email) " \
                             "VALUES ($1, $2, $3, $4, $5)";
        txn.exec_params(insert, username, nickname, hashedPassword, keyHex, email);
        txn.commit();

        std::cout << "insert user " << username << " successfully." << std::endl;
        return 0;
    }

    int PgDB::checkPassword(std::string username, std::string password) {
        // 从数据库中调取用户信息
        pqxx::work txn(*db);
        std::string query = "SELECT password_sha FROM public.users WHERE username=$1";
        pqxx::result result = txn.exec_params(query, username);
        if (result.empty()) return 2;
        std::string realpwd = result.begin()[0].as<std::string>();

        // 将读取到的十六进制字符串重新编码
        std::string pwd;
        for (size_t i = 2; i < realpwd.length(); i += 2) {
            char byte = (char) std::stoi(realpwd.substr(i, 2), nullptr, 16);
            pwd.push_back(byte);
        }

        // 将用户传输的密码进行SHA256
        CryptoPP::SHA256 hash;
        std::string hashedPassword;
        CryptoPP::StringSource(password, true,
                               new CryptoPP::HashFilter(hash,
                                                        new CryptoPP::HexEncoder(
                                                                new CryptoPP::StringSink(hashedPassword), false
                                                        )
                               )
        );
        // 比较真实SHA和输入SHA
        if (pwd != hashedPassword) return 3;

        // 重新生成新的随机key
        std::string keyHex = AccessToken::generateKey();

        // 更新数据库
        query = "UPDATE public.users SET key = $1, last_login = current_timestamp WHERE username = $2;";
        txn.exec_params(query, keyHex, username);
        txn.commit();
        return 0;
    }

    int PgDB::askKeyWithName(std::string username, std::string &key) {
        // 查询key
        pqxx::work txn(*db);
        std::string query = "SELECT key FROM public.users WHERE username = $1;";
        pqxx::result result = txn.exec_params(query, username);
        if (result.empty()) return 1;
        std::string hexString = result.begin()["key"].as<std::string>();
        key.clear();
        for (size_t i = 2; i < hexString.length(); i += 2) {
            char byte = (char) std::stoi(hexString.substr(i, 2), nullptr, 16);
            key.push_back(byte);
        }
        return 0;
    }

    int PgDB::askKeyWithId(std::string id, std::string &key) {
        if (id.empty()) return 2;
        // 查询key
        pqxx::work txn(*db);
        std::string query = "SELECT key FROM public.users WHERE id = $1;";
        pqxx::result result = txn.exec_params(query, id);
        if (result.empty()) return 2;
        std::string hexString = result.begin()["key"].as<std::string>();
        key.clear();
        for (size_t i = 2; i < hexString.length(); i += 2) {
            char byte = (char) std::stoi(hexString.substr(i, 2), nullptr, 16);
            key.push_back(byte);
        }
        return 0;
    }

    int PgDB::askId(std::string username, std::string &id) {
        pqxx::work txn(*db);
        std::string query = "SELECT id FROM public.users WHERE username = $1;";
        pqxx::result result = txn.exec_params(query, username);
        if (result.empty()) return 2;
        id = result[0][0].as<std::string>();
        return 0;
    }

    int PgDB::queryUsers(std::string itemName, std::string conditionName, std::string conditionValue,
                         std::string &ans) {
        pqxx::work txn(*db);
        std::string query = "SELECT " + itemName + " FROM public.users WHERE " + conditionName + " = $1;";
        pqxx::result result = txn.exec_params(query, conditionValue);
        if (result.empty()) return 500;
        ans = result[0][0].as<std::string>();
        return 0;
    }

    void PgDB::close() {

    }

    nlohmann::json PgDB::getOccupationList(std::string schema) const {
        pqxx::work txn(*db);
        std::string query = "SELECT * FROM " + schema + ".occupations WHERE public = true ORDER BY id;";
        pqxx::result result = txn.exec_params(query);
        nlohmann::json ans;
        for (pqxx::row row: result) {
            ans.push_back({
                                  {"id",          row["id"].as<int>()},
                                  {"name",        row["occupation_name"].as<std::string>()},
                                  {"description", row["description"].as<std::string>()},
                                  {"cal",         row["cal"].as<std::string>()},
                                  {"skill_id_1",  nlohmann::json::parse(
                                          array2json(row["skill_id_1"].as<std::string>()))},
                                  {"skill_id_2",  nlohmann::json::parse(
                                          array2json(row["skill_id_2"].as<std::string>()))},
                                  {"skill_id_3",  nlohmann::json::parse(
                                          array2json(row["skill_id_3"].as<std::string>()))},
                                  {"skill_id_4",  nlohmann::json::parse(
                                          array2json(row["skill_id_4"].as<std::string>()))},
                                  {"skill_id_5",  nlohmann::json::parse(
                                          array2json(row["skill_id_5"].as<std::string>()))},
                                  {"skill_id_6",  nlohmann::json::parse(
                                          array2json(row["skill_id_6"].as<std::string>()))},
                                  {"skill_id_7",  nlohmann::json::parse(
                                          array2json(row["skill_id_7"].as<std::string>()))},
                                  {"skill_id_8",  nlohmann::json::parse(
                                          array2json(row["skill_id_8"].as<std::string>()))},
                          });
        }
        return ans;
    }

    int PgDB::getSkillList(std::string schema, std::vector<Skill> &skills) const {
        pqxx::work txn(*db);

        std::string query = "SELECT * FROM " + schema +
                            ".skills ORDER BY id;";
        pqxx::result result = txn.exec_params(query);
        std::cout << "end query" << std::endl;
        for (pqxx::row row: result) {
            skills.emplace_back(schema, row);
        }
        std::cout << "end getSkillList" << std::endl;
        return 0;
    }

    int PgDB::insertRole(nlohmann::json data, std::string rule, int userId) const {
        pqxx::work txn(*db);
        std::string query = "INSERT INTO public.roles (user_id, schema) VALUES ($1, $2)";
        txn.exec_params(query, userId, rule);
        int id;
        if (rule == "coc7th") {
            id = txn.exec("SELECT currval('public.roles_id_seq')")[0][0].as<int>();
            query = "INSERT INTO coc7th.roles (" \
                    "id, " \
                    "user_id, " \
                    "role_name, " \
                    "role_nick, " \
                    "occupation_id, " \
                    "age, " \
                    "gender, " \
                    "birthday, " \
                    "birthplace_name, " \
                    "residence_name, " \
                    "strength, " \
                    "constitution, " \
                    "dexterity, " \
                    "size, " \
                    "education, " \
                    "appearance, " \
                    "intelligence, " \
                    "power, " \
                    "lucky, " \
                    "description, " \
                    "significant_person, " \
                    "significant_place, " \
                    "belief, " \
                    "valuables, " \
                    "traits, " \
                    "wounds, " \
                    "madness, " \
                    "background) VALUES (" \
                    "$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, " \
                    "$11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28)";
            std::cout << data.dump() << std::endl;
            std::cout <<
                      data["description"].get<std::string>() << ' ' <<
                      data["significantPerson"].get<std::string>() << ' ' <<
                      data["significantPlace"].get<std::string>() << ' ' <<
                      data["belief"].get<std::string>() << ' ' <<
                      data["valuables"].get<std::string>() << ' ' <<
                      data["traits"].get<std::string>() << ' ' <<
                      data["wounds"].get<std::string>() << ' ' <<
                      data["madness"].get<std::string>() << ' ' <<
                      data["background"].get<std::string>() << std::endl;
            try {
                txn.exec_params(query,
                                id,
                                userId,
                                data["rolename"].get<std::string>(),
                                data["nickname"].get<std::string>(),
                                data["occupation"].get<int>(),
                                data["age"].get<int>(),
                                data["gender"].get<int>(),
                                data["birthdate"].get<std::string>(),
                                data["birthplace"].get<std::string>(),
                                data["residence"].get<std::string>(),
                                data["attributes"]["STR"].get<int>(),
                                data["attributes"]["CON"].get<int>(),
                                data["attributes"]["DEX"].get<int>(),
                                data["attributes"]["SIZ"].get<int>(),
                                data["attributes"]["EDU"].get<int>(),
                                data["attributes"]["APP"].get<int>(),
                                data["attributes"]["INT"].get<int>(),
                                data["attributes"]["POW"].get<int>(),
                                data["attributes"]["LUC"].get<int>(),
                                data["description"].get<std::string>(),
                                data["significantPerson"].get<std::string>(),
                                data["significantPlace"].get<std::string>(),
                                data["belief"].get<std::string>(),
                                data["valuables"].get<std::string>(),
                                data["traits"].get<std::string>(),
                                data["wounds"].get<std::string>(),
                                data["madness"].get<std::string>(),
                                data["background"].get<std::string>());
            } catch (std::exception& e) {
                std::cout << e.what() << std::endl;
            }
            query = "INSERT INTO coc7th.skill_belong (role_id, skill_id, value) VALUES ($1, $2, $3);";
            std::cout << nlohmann::json::parse(data["skillAdd"].get<std::string>()).dump() << std::endl;
            nlohmann::json skillAdd = nlohmann::json::parse(data["skillAdd"].get<std::string>());
            for (const auto &obj: skillAdd.items()) {
                std::cout << obj.key() << ' ' << skillAdd[obj.key()].get<int>() << std::endl;
                txn.exec_params(query, id, std::stoi(obj.key()), obj.value().get<int>());
            }
            txn.commit();
        }
        return 0;
    }

    int PgDB::roleList(int userId, std::string ord, int limit, int offset, nlohmann::json &output) const {
        pqxx::work txn(*db);
        std::string query = "SELECT * FROM public.roles "
                            "JOIN coc7th.roles ON public.roles.schema='coc7th' AND public.roles.id = coc7th.roles.id "
                            "WHERE public.roles.user_id = " + std::to_string(userId) +
                            " ORDER BY " + ord +
                            " LIMIT " + std::to_string(limit) +
                            " OFFSET " + std::to_string(offset);
        pqxx::result result = txn.exec(query);

        query = "SELECT COUNT(*) FROM public.roles WHERE public.roles.user_id = " + std::to_string(userId) + ';';
        int cnt = txn.exec(query)[0][0].as<int>();

        output["cnt"] = cnt;
        output["roleList"] = nlohmann::json::parse("[]");
        nlohmann::json role;
        for (pqxx::row row : result) {
            role = nlohmann::json::parse("{}");
            query = "SELECT "
                    "   coc7th.skill_belong.skill_id AS skill_id,"
                    "   COALESCE(coc7th.skill_belong.value, coc7th.skills.initial) AS skillPoint"
                    " FROM coc7th.skill_belong"
                    " RIGHT JOIN coc7th.skills ON coc7th.skill_belong.skill_id = coc7th.skills.id"
                    " WHERE coc7th.skill_belong.role_id = $1 AND COALESCE(coc7th.skill_belong.value, coc7th.skills.initial) >= 50;";
            pqxx::result skills = txn.exec_params(query, row["id"].as<int>());

            role["skill"] = nlohmann::json::parse("{}");
            for (pqxx::row skill : skills) {
                role["skill"][skill["skill_id"].as<std::string>()] = skill["skillPoint"].as<int>();
            }

            role["rule"] = row["schema"].as<std::string>();
            role["roleId"] = row["id"].as<int>();
            role["rolename"] = row["role_name"].as<std::string>();
            role["occupationId"] = row["occupation_id"].as<int>();
            role["nickname"] = row["role_nick"].as<std::string>();
            role["age"] = row["age"].as<std::string>();
            role["background"] = myTruncateString(row["background"].as<std::string>(), 100);
            output["roleList"].push_back(role);
        }
        return 0;
    }
    int PgDB::queryRole(int roleId, int userId, std::string schema, nlohmann::json &output) const {
        pqxx::work txn(*db);
        std::string query = "SELECT * FROM coc7th.roles WHERE coc7th.roles.id = $1 AND coc7th.roles.user_id=$2;";
        std::cout << query << ' ' << roleId << ' ' << userId << std::endl;
        pqxx::result role = txn.exec_params(query, roleId, userId);
        if (role.size() == 0) {
            output["status"] = 8;
        }
        auto row = role[0];
        output["id"] = row["id"].as<int>();
        output["rolename"] = row["role_name"].as<std::string>();
        output["nickname"] = row["role_nick"].as<std::string>();
        output["gender"] = row["gender"].as<int>();
        output["occupationId"] = row["occupation_id"].as<int>();
        output["age"] = row["age"].as<int>();
        output["birthday"] = row["birthday"].as<std::string>();
        output["birthplace"] = row["birthplace_name"].as<std::string>();
        output["residence"] = row["residence_name"].as<std::string>();

        output["strength"] = row["strength"].as<int>();
        output["constitution"] = row["constitution"].as<int>();
        output["size"] = row["size"].as<int>();
        output["dexterity"] = row["dexterity"].as<int>();
        output["education"] = row["education"].as<int>();
        output["intelligence"] = row["intelligence"].as<int>();
        output["power"] = row["power"].as<int>();
        output["appearance"] = row["appearance"].as<int>();
        output["lucky"] = row["lucky"].as<int>();

        output["background"] = row["background"].as<std::string>();
        output["description"] = row["description"].as<std::string>();
        output["significantPerson"] = row["significant_person"].as<std::string>();
        output["significantPlace"] = row["significant_place"].as<std::string>();
        output["belief"] = row["belief"].as<std::string>();
        output["traits"] = row["traits"].as<std::string>();
        output["madness"] = row["madness"].as<std::string>();
        output["valuables"] = row["valuables"].as<std::string>();
        output["wounds"] = row["wounds"].as<std::string>();

        query = "SELECT "
                "   coc7th.skills.id AS skill_id, "
                "   COALESCE(skill_belong.value, coc7th.skills.initial) AS skillPoint "
                "FROM ("
                "   SELECT * FROM coc7th.skill_belong "
                "   WHERE role_id = $1) as skill_belong "
                "RIGHT JOIN coc7th.skills ON skill_belong.skill_id = coc7th.skills.id "
                "ORDER BY skillPoint DESC";
        pqxx::result skills = txn.exec_params(query, roleId);
        output["skillList"] = nlohmann::json::parse("[]");
        for (auto const& row : skills) {
            output["skillList"].push_back({
                                                  {"skillId", row["skill_id"].as<int>()},
                                                  {"skillPoint", row["skillPoint"].as<int>()}
            });
        }
        return 0;
    }
}
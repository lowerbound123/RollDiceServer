//
// Created by Tony Chow on 2023/12/1.
//
#include "userManager.h"
#include "pqxx/pqxx"
#include "dicedb.h"
#include "string"
#include "json.hpp"
#include "iostream"
#include "accessToken.h"
#include "regex"
#include "chrono"
#include "typeindex"
#include "iomanip"
#include "ctime"
#include "crypto++/aes.h"
#include "crypto++/filters.h"
#include "crypto++/hex.h"
#include "crypto++/osrng.h"
#include "crypto++/secblock.h"

nlohmann::json UserManager::addUser(Dicedb::PgDB db, nlohmann::json data) {
    std::string username = data["username"];
    std::string nickname = data["nickname"];
    std::string password = data["sha"];
    std::string email = data["email"];

    int result = db.insertUser(username, nickname, password, email);
    nlohmann::json ans;

    // 根据不同的结果返回不同的包
    switch (result) {
        case 0:
            std::cout << "用户 " << username << " 成功添加" << std::endl;
            ans["status"] = 0;
            break;
        case 1:
            std::cout << "用户 " << username << " 已经存在" << std::endl;
            ans["status"] = 1;
            break;
    }
    return ans;
}

nlohmann::json UserManager::validateUser(Dicedb::PgDB db, nlohmann::json data) {
    std::string username = data["username"];
    std::string password = data["sha"];
    nlohmann::json ans;
    std::string keyHex, id;

    int result = db.checkPassword(username, password);
    switch (result) {
        case 0:
            std::cout << "用户 " << username << " 登录成功" << std::endl;
            ans["status"] = 0;
            db.askId(username, id);
            db.askKeyWithName(username, keyHex);
            ans["accessToken"] = AccessToken::encryptString(id, keyHex);
            ans["id"] = id;
            break;
        case 2:
            std::cout << "用户 " << username << " 不存在" << std::endl;
            ans["status"] = 2;
            break;
        case 3:
            std::cout << "用户 " << username << " 输入的密码有误" << std::endl;
            ans["status"] = 3;
            break;
    }
    return ans;
}

std::chrono::system_clock::time_point parseTime(const std::string& timeStr) {
    std::tm tm = {};
    std::istringstream ss(timeStr);
    ss >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S");

    // 获取时区
    std::string timeZoneStr;
    ss >> timeZoneStr;

    // 转换时区字符串为分钟
    int timeZoneMinutes = 0;
    if (timeZoneStr.size() >= 6) {
        int sign = (timeZoneStr[0] == '-') ? -1 : 1;
        int hours = std::stoi(timeZoneStr.substr(1, 2));
        int minutes = std::stoi(timeZoneStr.substr(4, 2));
        timeZoneMinutes = sign * (hours * 60 + minutes);
    }

    // 转换为时间点
    auto timePoint = std::chrono::system_clock::from_time_t(std::mktime(&tm));
    timePoint += std::chrono::minutes(timeZoneMinutes);
    return timePoint;
}

nlohmann::json UserManager::checkToken(Dicedb::PgDB db, nlohmann::json data) {
    std::string id = data["id"], inner_id;
    std::string token = data["accessToken"];
    std::string key, inner_key, timestamp, str;
    nlohmann::json ans;
    if (db.askKeyWithId(id, key) == 2) {
        std::cout << "id " + id + " 不存在" << std::endl;
        ans["status"] = 1;
        return ans;
    }
    try {
        str = AccessToken::decryptString(token, key);
    } catch (const std::exception& e) {
        ans["status"] = 4;
        return ans;
    }

    std::regex pattern(R"((\d+) (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+ \+\d{2}:\d{2}) ([0-9A-Fa-f]+))");
    std::smatch match;
    if (!std::regex_match(str, match, pattern)) {
        ans["status"] = 4;
        return ans;
    }
    inner_id = match[1];
    timestamp = match[2];
    inner_key = match[3];
    if (id != inner_id) {
        ans["status"] = 5;
        return ans;
    }
    if (inner_key != key) {
        ans["status"] = 7;
        return ans;
    }
    ans["status"] = 0;
    std::string nickname;
    db.queryUsers("nickname", "id", id, nickname);
    ans["nickname"] = nickname;
    std::cout << nickname << " Visit with token successfully" << std::endl;
    return ans;
}

std::string getExpireTime() {
    std::time_t now = std::time(nullptr);
    std::time_t expire_time = now + 15 * 24 * 60 * 60;
    std::stringstream expire;
    expire << std::put_time(std::gmtime(&expire_time), "%a, %d %b %Y %H:%M:%S GMT");
    return expire.str();
}

std::string UserManager::getCookie(Dicedb::PgDB db, std::string id) {
    std::string username, keyHex, ans;
    db.queryUsers("username", "id", id, username);
    db.askId(username, id);
    db.askKeyWithName(username, keyHex);

    ans += "accessToken=" + AccessToken::encryptString(id, keyHex) + "; expires=" + getExpireTime() + ";";
    ans += "id=" + id + "; expire=" +getExpireTime() + ";";
    return ans;
}
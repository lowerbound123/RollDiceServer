#include "httplib.h"
#include "json.hpp"
#include "dicedb.h"
#include "accessToken.h"
#include "userManager.h"
#include "roleManager.h"
#include <chrono>
#include <ctime>
#include "getopt.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "basic_class.h"
#include "vector"
#include "algorithm"

using json = nlohmann::json;

void outputTime() {
    auto currentTimePoint = std::chrono::system_clock::now();
    auto currentTimeMicro = std::chrono::time_point_cast<std::chrono::microseconds>(currentTimePoint);

    std::time_t currentTime = std::chrono::system_clock::to_time_t(currentTimePoint);
    auto microSeconds = std::chrono::duration_cast<std::chrono::microseconds>(currentTimePoint.time_since_epoch()) % std::chrono::seconds(1);

    struct tm* localTime = std::localtime(&currentTime);

    std::cout << "===========================================================" << std::endl;
    std::cout << "Time: " << std::asctime(localTime) << "Microseconds: " << microSeconds.count() << std::endl;
}

nlohmann::json parse_cookie_string(const std::string& cookie_string) {
    nlohmann::json cookie_json;

    std::istringstream ss(cookie_string);
    std::string token;

    while (std::getline(ss, token, ';')) {
        // 分割键值对
        size_t equal_pos = token.find('=');
        if (equal_pos != std::string::npos) {
            std::string key = token.substr(0, equal_pos);
            std::string value = token.substr(equal_pos + 1);

            // 移除首尾空格
            key.erase(0, key.find_first_not_of(" \t\n\r\f\v"));
            key.erase(key.find_last_not_of(" \t\n\r\f\v") + 1);
            value.erase(0, value.find_first_not_of(" \t\n\r\f\v"));
            value.erase(value.find_last_not_of(" \t\n\r\f\v") + 1);

            // 添加到 JSON 对象
            cookie_json[key] = value;
        }
    }
    if (!cookie_json.contains("accessToken")) cookie_json["accessToken"] = "";
    if (!cookie_json.contains("id")) cookie_json["id"] = 0;
    return cookie_json;
}

int main(int argc, char* argv[]) {
    int opt;
    std::string loginQuery = "";
    int port = 8000;
    const char* short_options = "d:u:p:P:";
    const struct option long_options[] = {
            {"password", required_argument, 0, 'p'},
            {"username", required_argument, 0, 'u'},
            {"database", required_argument, 0, 'd'},
            {"Port", required_argument, 0, 'P'},
            {0, 0, 0, 0}
    };
    while ((opt = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
        switch (opt) {
            case 'd':
                loginQuery += "dbname=" + std::string(optarg) + " ";
                break;
            case 'u':
                loginQuery += "user=" + std::string(optarg) + " ";
                break;
            case 'p':
                loginQuery += "password=" + std::string(optarg) + " ";
                break;
            case 'P':
                port = std::atoi(optarg);
        }
    }
    Dicedb::PgDB db{};
    db.connect(loginQuery);
//    db.connect("dicedb", "zhouyx", "20030425");
    std::cout << "Current_time: " << db.get_current_time() << std::endl;
    std::cout << "UTC time: " << AccessToken::getUTCTime() << std::endl;
    httplib::Server svr;
    // 创建 httplib 的服务器实例

    svr.set_default_headers({
                                    {"Access-Control-Allow-Origin", "*"},
                                    {"Access-Control-Allow-Methods", "delete, post, get, options"},
                                    {"Access-Control-Allow-Headers", "Content-Type"},
    });
    svr.Options("/register",[](const httplib::Request& req, httplib::Response& res) {
        outputTime();
        std::cout << "Someone want to create a count." << std::endl;
        res.status = 200;
    });

    // 处理 POST 请求
    svr.Post("/register", [db](const httplib::Request& req, httplib::Response& res) {
        // 解析 JSON 数据
        auto json_data = json::parse(req.body);
        // 从 JSON 中获取数据
        std::cout << "User " << json_data["username"] << " want to create a count." << std::endl;
        std::cout << "Pwd " << json_data["sha"] << std::endl;
        json response = UserManager::addUser(db, json_data);

        // 将 JSON 数据作为响应发送给客户端
        res.set_content(response.dump(), "application/json");
    });

    svr.Options("/login",[](const httplib::Request& req, httplib::Response& res) {
        outputTime();
        std::cout << "Someone want to login." << std::endl;
        res.status = 200;
    });

    // 处理 POST 请求
    svr.Post("/login", [db](const httplib::Request& req, httplib::Response& res) {
        // 解析 JSON 数据
        auto json_data = json::parse(req.body);
        // 从 JSON 中获取数据
        json response = UserManager::validateUser(db, json_data);

        // 将 JSON 数据作为响应发送给客户端
        res.set_content(response.dump(), "application/json");
    });

    svr.Options("/check",[](const httplib::Request& req, httplib::Response& res) {
        outputTime();
        std::cout << "src = Check method = Options origin = " << req.get_header_value("Origin") << std::endl;
        res.status = 200;
    });

    svr.Post("/check", [db](const httplib::Request& req, httplib::Response& res) {
        auto json_data = json::parse(req.body);
        std::cout << "Someone want to visit the website with token." << std::endl;
        // 从 JSON 中获取数据
        json response = UserManager::checkToken(db, json_data);
//        TODO: 增加对Timestamp的check
        // 将 JSON 数据作为响应发送给客户端
        res.set_content(response.dump(), "application/json");
    });

    svr.Options("/occupationList", [](const httplib::Request& req, httplib::Response& res) {
        outputTime();
        std::cout << "Someone want the occupation list." << std::endl;
        res.status = 200;
    });

    svr.Post("/occupationList", [db](const httplib::Request& req, httplib::Response& res) {
        std::cout << "Someone want to get OccupationList." << std::endl;

        auto json_data = json::parse(req.body);
        // 从 JSON 中获取数据
        json response = UserManager::checkToken(db, json_data);
        if (response["status"].get<int>() == 0) {
            response["occupationList"] = db.getOccupationList(json_data["rule"]);
        }
        std::cout << response.dump() << std::endl;
        // 将 JSON 数据作为响应发送给客户端
        res.set_content(response.dump(), "application/json");
    });

    svr.Options("/skillList", [](const httplib::Request& req, httplib::Response& res) {
        outputTime();
        std::cout << "method: Options, path: /skillList" << std::endl;
        res.status = 200;
    });

    svr.Post("/skillList", [db](const httplib::Request& req, httplib::Response& res) {
        std::cout << "method: Post, path: /skillList" << std::endl;

        auto json_data = json::parse(req.body);
        json response = UserManager::checkToken(db, json_data);
        if (response["status"].get<int>() == 0) {
            std::vector<Skill> skills;
            db.getSkillList(json_data["rule"], skills);
            response["skillList"] = skills;
        }
        std::cout << response.dump() << std::endl;
        res.set_content(response.dump(), "application/json");
    });

    svr.Options("/roleCreate", [](const httplib::Request& req, httplib::Response& res) {
        outputTime();
        std::cout << "method: Options, path: /roleCreate" << std::endl;
        res.status = 200;
    });

    svr.Post("/roleCreate", [db](const httplib::Request& req, httplib::Response& res) {
        std::cout << "method: Post, path: /roleCreate" << std::endl;

        auto json_data = json::parse(req.body);
        json response = UserManager::checkToken(db, json_data);
        std::string rule = json_data["rule"].get<std::string>();
        int id = std::stoi(json_data["id"].get<std::string>());
        std::transform(rule.begin(), rule.end(), rule.begin(), ::tolower);
        if (response["status"].get<int>() == 0) {
            db.insertRole(json_data, rule, id);
        }
        res.set_content(response.dump(), "application/json");
    });

    svr.Options("/roleList", [](const httplib::Request& req, httplib::Response& res) {
        std::cout << "method: Options, path: /roleList" << std::endl;
        res.status = 200;
    });

    svr.Post("/roleList", [db](const httplib::Request& req, httplib::Response& res) {
        std::cout << "method: Post, path: /roleList" << std::endl;
        outputTime();
        auto json_data = json::parse(req.body);
        json response = UserManager::checkToken(db, json_data);
        int id = std::stoi(json_data["id"].get<std::string>());
        if (response["status"].get<int>() == 0) {
            db.roleList(id,
                        json_data["ord"].get<std::string>(),
                        json_data["limit"].get<int>(),
                        json_data["offset"].get<int>(),
                        response);
        }
        std::cout << "successfully end with JSON" << std::endl;
        res.set_content(response.dump(), "application/json");
        outputTime();
    });

    svr.Options("/queryRole", [](const httplib::Request& req, httplib::Response& res) {
        std::cout << "method: Options, path: /queryRole" << std::endl;
        res.status = 200;
    });

    svr.Post("/queryRole", [db](const httplib::Request& req, httplib::Response& res) {
        std::cout << "method: Post, path: /queryRole" << std::endl;
        outputTime();
        auto json_data = json::parse(req.body);
        json response = UserManager::checkToken(db, json_data);
        int id = std::stoi(json_data["id"].get<std::string>());
        if (response["status"].get<int>() == 0) {
            db.queryRole(
                    json_data["roleId"].get<int>(),
                    id,
                    json_data["rule"].get<std::string>(),
                    response);
        }
        std::cout << "successfully end with JSON" << std::endl;
        std::cout << response.dump() << std::endl;
        res.set_content(response.dump(), "application/json");
        outputTime();
    });

    // 启动服务器，监听在指定端口
    svr.listen("0.0.0.0", port);


    return 0;
}

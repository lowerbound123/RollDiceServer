//
// Created by Tony Chow on 2023/12/10.
//

#ifndef ROLLDICE_BASIC_CLASS_H
#define ROLLDICE_BASIC_CLASS_H
#include "string"
#include "json.hpp"
#include "pqxx/pqxx"

class Skill {
private:
    int id, initial;
    std::string name, description, rule;

public:
    Skill(std::string _rule, pqxx::row row) {
        rule = _rule;
        if (rule == "coc7th") {
            id = row["id"].as<int>();
            initial = row["initial"].as<int>();
            name = row["skill_name"].as<std::string>();
            description = row["description"].as<std::string>();
        }
    }
    Skill() {
        id = 0;
        initial = 0;
        name = "";
        description = "";
    }
    void setId(int x) {
        id = x;
    }
    void setInitial(int x) {
        initial = x;
    }
    void setName(std::string x) {
        name = x;
    }
    void setDescription(std::string x) {
        description = x;
    }
    int getId() { return id; }
    int getInitial() { return initial; }
    std::string getName() { return name; }
    std::string getDescription() { return description; }
    friend void to_json(nlohmann::json &j, const Skill& obj) {
        if (obj.rule == "coc7th") {
            j = nlohmann::json{{"id", obj.id}, {"initial", obj.initial}, {"name", obj.name}, {"description", obj.description}};
        }
    }
    friend void from_json(const nlohmann::json &j, Skill& obj) {
        obj.id = j.at("id").get<int>();
        obj.initial = j.at("initial").get<int>();
        obj.name = j.at("name").get<std::string>();
        obj.description = j.at("description").get<std::string>();
    }
};

std::string myTruncateString(const std::string& s, int maxLength = 100);

#endif //ROLLDICE_BASIC_CLASS_H

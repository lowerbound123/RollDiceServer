//
// Created by Tony Chow on 2023/12/4.
//

#ifndef ROLLDICE_ACCESSTOKEN_H
#define ROLLDICE_ACCESSTOKEN_H

#include "string"
#include "crypto++/hex.h"

namespace AccessToken {
    std::string generateKey();

    std::string getUTCTime();

    std::string encryptString(const std::string& id, const std::string keyHex);

    std::string decryptString(const std::string& str, const std::string keyHex);
}
#endif //ROLLDICE_ACCESSTOKEN_H

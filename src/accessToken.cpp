//
// Created by Tony Chow on 2023/12/4.
//

#include "accessToken.h"
#include "string"
#include "pqxx/pqxx"
#include "dicedb.h"
#include "chrono"
#include "iostream"
#include "sstream"

#include "crypto++/aes.h"
#include "crypto++/filters.h"
#include "crypto++/hex.h"
#include "crypto++/osrng.h"
#include "crypto++/secblock.h"
#include "crypto++/modes.h"


namespace AccessToken {
//    std::string Token::getUTCTime() {
//        auto currentTimePoint = std::chrono::system_clock::now();
//        auto highResTimePoint = std::chrono::time_point_cast<std::chrono::microseconds>(currentTimePoint);
//        auto timestamp = highResTimePoint.time_since_epoch().count();
//        auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(highResTimePoint.time_since_epoch() % std::chrono::seconds(1)).count();
//        auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(highResTimePoint.time_since_epoch() % std::chrono::milliseconds(1)).count();
//        std::time_t now_c = std::chrono::system_clock::to_time_t(currentTimePoint);
//        std::tm* tmStruct = std::gmtime(&now_c);
//        std::stringstream ss;
//        ss << std::put_time(tmStruct, "%Y-%m-%d %H:%M:%S") << "." << std::setfill('0') << std::setw(6) << microseconds << " +00:00";
//        return ss.str(); // 输出 UTC 时间
//    }
//
//    void Token::generateKey() {
//        CryptoPP::AutoSeededRandomPool prng;
//        encodeKey.resize(CryptoPP::AES::DEFAULT_KEYLENGTH);
//        prng.GenerateBlock(encodeKey, encodeKey.size());
//    }
//
//    void Token::setKey(std::string key) {
//        std::string tmpKey;
//        CryptoPP::StringSource(key, true,
//                               new CryptoPP::HexDecoder(
//                                       new CryptoPP::StringSink(tmpKey)
//                               )
//        );
//        encodeKey = CryptoPP::SecByteBlock(reinterpret_cast<const CryptoPP::byte*>(key.data()), CryptoPP::AES::DEFAULT_KEYLENGTH);
//    }
//
//    void Token::setKey(CryptoPP::SecByteBlock key) {
//        encodeKey = key;
//    }
//
//    void Token::setStr(std::string str) {
//        originStr = str;
//    }
//
//    void Token::setEncodeStr(std::string str) {
//        encodeStr = str;
//    }
//
//    int Token::getHexKey(std::string &key) {
//        if (encodeKey.empty()) return 1;
//        CryptoPP::HexEncoder hex(new CryptoPP::StringSink(key));
//        hex.Put(encodeKey.data(), encodeKey.size());
//        hex.MessageEnd();
//        return 0;
//    }
//
//    int Token::getEncodeStr(std::string &str) {
//        if (!encodeStr.empty()) {
//            str = encodeStr;
//            return 0;
//        }
//        if (encodeKey.empty() || originStr.empty()) return 1;
//
//    }

    std::string generateKey() {
        CryptoPP::AutoSeededRandomPool prng;
        CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
        prng.GenerateBlock(key, key.size());
        std::string keyHex;
        CryptoPP::HexEncoder hex(new CryptoPP::StringSink(keyHex));
        hex.Put(key.data(), key.size());
        hex.MessageEnd();
        return keyHex;
    }

    std::string getUTCTime() {
        auto currentTimePoint = std::chrono::system_clock::now();
        auto highResTimePoint = std::chrono::time_point_cast<std::chrono::microseconds>(currentTimePoint);
        auto timestamp = highResTimePoint.time_since_epoch().count();
        auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(highResTimePoint.time_since_epoch() % std::chrono::seconds(1)).count();
        auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(highResTimePoint.time_since_epoch() % std::chrono::milliseconds(1)).count();
        std::time_t now_c = std::chrono::system_clock::to_time_t(currentTimePoint);
        std::tm* tmStruct = std::gmtime(&now_c);
        std::stringstream ss;
        ss << std::put_time(tmStruct, "%Y-%m-%d %H:%M:%S") << "." << std::setfill('0') << std::setw(6) << microseconds << " +00:00";
        return ss.str(); // 输出 UTC 时间
    }

    std::string encryptString(const std::string &id, const std::string keyHex) {
        std::string output;
        // 将十六进制字符串格式的key重新编码
        std::string key;
        CryptoPP::StringSource(keyHex, true,
                               new CryptoPP::HexDecoder(
                                       new CryptoPP::StringSink(key)
                               )
        );
        CryptoPP::SecByteBlock decodedKey(reinterpret_cast<const CryptoPP::byte*>(key.data()), CryptoPP::AES::DEFAULT_KEYLENGTH);
        // 生成待加密字符串
        std::string str = id + " " + getUTCTime() + " " + keyHex;

        // 加密字符串
        CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption aesEncryption;
        aesEncryption.SetKey(decodedKey, decodedKey.size());

        std::string cipherstr;
        // 加密并编码为十六进制字符串
        CryptoPP::StringSource(str, true,
                               new CryptoPP::StreamTransformationFilter(aesEncryption,
                                                                        new CryptoPP::HexEncoder(
                                                                                new CryptoPP::StringSink(cipherstr),
                                                                                false // 不包含行尾的换行符
                                                                        )
                               )
        );

        return cipherstr;
    }

    std::string decryptString(const std::string& str, const std::string keyHex) {
        // 将密钥重新编码
        std::string key;
        CryptoPP::StringSource(keyHex, true,
                               new CryptoPP::HexDecoder(
                                       new CryptoPP::StringSink(key)
                               )
        );
        CryptoPP::SecByteBlock decodedKey(reinterpret_cast<const CryptoPP::byte*>(key.data()), CryptoPP::AES::DEFAULT_KEYLENGTH);

        // 解码为二进制字符串
        std::string binaryStr;
        CryptoPP::StringSource(str, true,
                               new CryptoPP::HexDecoder(
                                       new CryptoPP::StringSink(binaryStr)
                               )
        );

        // 生成AES解码器并解码
        CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption aesDecryption;
        aesDecryption.SetKey(decodedKey, decodedKey.size());
        std::string originStr;
        CryptoPP::StringSource(binaryStr, true,
                               new CryptoPP::StreamTransformationFilter(aesDecryption,
                                                                        new CryptoPP::StringSink(originStr)
                               )
        );
        return originStr;
    }
}
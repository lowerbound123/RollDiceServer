//
// Created by Tony Chow on 2023/12/11.
//


#include "basic_class.h"
#include "string"
#include "unicode/unistr.h"

std::string myTruncateString(const std::string& s, int maxLength) {
    icu::UnicodeString ustr = icu::UnicodeString::fromUTF8(s);
    std::string truncated;
    if (ustr.length() > maxLength) {
        ustr.truncate((int32_t)maxLength);
        // 将 Unicode 字符串转换为 UTF-8 字符串
        ustr.toUTF8String(truncated);
        // 在末尾增加...
        truncated += "...";
    } else {
        // 如果长度未超过 maxLength，直接返回原字符串
        return s;
    }

    return truncated;
}
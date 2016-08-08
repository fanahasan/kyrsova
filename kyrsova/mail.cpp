#include <iostream>
#include <string>
#include <stdlib.h>
#include <fstream>
#include <vector>
#include <ctime>
#include <unordered_map>
#include <omp.h>
#include <thread>
//#include <unistd.h>
#include <cstring>
#include <sys/stat.h>

#include "algorithms.h"

#pragma warning(disable:4996)

#define PATCH_CONFIG "d:\\config.txt"
#define PATCH_FIREWALL_LOG "d:\\test.txt"
// olololo
using namespace std;

class Block_firewall {
private:
	bool Blocked = false;
public:
	Block_firewall() {

	}
	Block_firewall(bool res) {
		Blocked = res;
	}
	bool Function_block() {
		string str = "iptables -A INPUT -j LOG --log-prefix \"INPUT packets\"";
		//cout << str << endl;
		if (system(str.c_str()) == 0) {
			Blocked = true;
			str = "iptables -A INPUT -j DROP";
			system(str.c_str());
			return true;
		}
		else {

		}
		return false;
	}
};

//read configuration files;

struct Port_And_Protocols {
	string protocol;
	unsigned short port;
	Port_And_Protocols(string _protocol, unsigned short _port) {
		protocol = _protocol;
		port = _port;
	}
};

struct Port_And_Protocol_And_ID {
	unsigned long long ID;
	string protocol;
	unsigned short port;
	Port_And_Protocol_And_ID(string _protocol, unsigned short _port, unsigned long long id) {
		protocol = _protocol;
		port = _port;
		ID = id;
	}
};

class Read_Config {
private:
	bool Read_ok = false;
	vector<string> str_config;
protected:
	int time_listem_data;
	vector<Port_And_Protocols> open_firewall;
	vector<Port_And_Protocols> listen_true_combination;
	vector<Port_And_Protocols> close_combination;
public:
	/* читаємо файл конфігурації, якщо його нема, то виходимо з конструктора, і змінюємо значення реад_ок на фолс*/
	Read_Config() {
		string str_tmp;
		ifstream in(PATCH_CONFIG, ios::in);
		if (!in.is_open()) {
			return;
		}
		else {
			while (!in.eof()) {
				getline(in, str_tmp);
				/*якщо це комент, то його треба ігнорити*/
				if (str_tmp[0] != '#')
					str_config.push_back(str_tmp);
			}
		}
		if (str_config.size() != 0) {
			Read_ok = true;
		}
		in.close();
	}
	int Rozborka_config() {
		int position_rivne = 0;
		string protocol;
		unsigned short port;
		if (Read_ok == false) {
			return (1);
		}
		else {
			string first_chast, last_chast;
			char * what;
			for (int i = 0; i < str_config.size(); i++) {
				position_rivne = str_config[i].find('=');
				if (position_rivne != -1) {
					first_chast = str_config[i].substr(0, position_rivne);
					last_chast = str_config[i].substr(position_rivne + 1);
					/*комбінація на відкриття порту protocol:port*/
					if (first_chast == "open_combination") {
						what = strtok(const_cast<char*>(last_chast.c_str()), " :=.,;");
						while (what != NULL) {
							protocol = what;
							what = strtok(NULL, " :=.,;");
							port = atoi(what);
							what = strtok(NULL, " :=.,;");
							//cout << "read protocol = " << protocol << " port = " << port << endl;
							protocol = To_upper_string(protocol);
							this->listen_true_combination.push_back(Port_And_Protocols(protocol, port));
						}
					}
					else {
						/*комбінація на закриття зєднання */
						if (first_chast == "close_combination") {
							what = strtok(const_cast<char*>(last_chast.c_str()), " :=.,;");
							while (what != NULL) {
								protocol = what;
								what = strtok(NULL, " :=.,;");
								port = atoi(what);
								what = strtok(NULL, " :=.,;");
								this->close_combination.push_back(Port_And_Protocols(protocol, port));
							}
						}
						else {
							/*час життя від отримання першого до останього пакету*/
							if (first_chast == "listen_time") {
								this->time_listem_data = atoi(last_chast.c_str());
							}
							else {
								/*які порти, або порт вікривати формат protocol:port*/
								if (first_chast == "open_port") {
									what = strtok(const_cast<char*>(last_chast.c_str()), " :=.,;");
									while (what != NULL) {
										protocol = what;
										what = strtok(NULL, " :=.,;");
										port = atoi(what);
										what = strtok(NULL, " :=.,;");
										this->open_firewall.push_back(Port_And_Protocols(protocol, port));
									}
								}
							}
						}
					}
				}
				else {
					cout << str_config[i] << endl;
				}
			}
			if (this->close_combination.size() == 0 || this->listen_true_combination.size() == 0 || this->open_firewall.size() == 0) {
				cout << "error, щось рівне 0 " << endl;
				return (2);
			}
			return 0;
		}
	}

	bool Edit_Kernal_Linux() {
		ofstream Edit("/etc/rsyslog.conf", ios::app);
		if (Edit.fail()) {
			cout << "редагування syslog завершилося помилкою" << endl;
			return false;
		}
		Edit << "kern.warning /var/log/iptables.log" << endl;
		Edit.flush();
		Edit.close();
		return true;
	}

	bool Create_file_config() {
		if (Edit_Kernal_Linux() == false) {
			cout << "редагування ядра завершилось крахом" << endl;
		}
		//mkdir("/etc/program/", S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
		ofstream out(PATCH_CONFIG, ios::out);
		if (!out.is_open()) {
			cout << "неможу створити/відкрити файл крнфігурації для запису" << endl;
			return false;
		}
		out << "#listen ports" << endl;
		out << "open_combination=tcp:3000, udp:4000, tcp:5000" << endl;
		out << "#close_combination" << endl;
		out << "close_combination=tcp:5000, udp:4000, tcp:3000" << endl;
		out << "#time listen second new packet" << endl;
		out << "listen_time=20" << endl;
		out << "#open protocol and port" << endl;
		out << "open_port=tcp:22" << endl;
		out.flush();
		return true;
	}
};

class General_works : public Read_Config {
private:
	unsigned long Size_end_file; // Реальний зафіксований розмір файлу
	unordered_map<string, vector<Port_And_Protocol_And_ID>> Users; // База "стуків" користувача
	unordered_map<string, time_t> Time_start; // час запису першого стуку для певної ІР адреси
	vector<string> Open_ports_ip; // База відкритих ІР адрес
	unordered_map<string, time_t> Start_listem_open_ip; // База часу, коли для підтримки лії звязку
	time_t time_tmp, time_last_clear_base, time_tmp_listen; // різні типу виміру часу

	bool True_Combination_Users_open(string ip_address) {
		for (int i = 0; i < this->listen_true_combination.size(); i++) {
			if (Users[ip_address][i].port != listen_true_combination[i].port || Users[ip_address][i].protocol != listen_true_combination[i].protocol) {
				return false;
			}
		}
		return true;
	}
	bool True_Combination_User_close(string ip_address) {
		for (int i = 0; i < this->close_combination.size(); i++) {
			if (Users[ip_address][i].port != this->close_combination[i].port || Users[ip_address][i].protocol != close_combination[i].protocol) {
				return false;
			}
		}
		return true;
	}

public:
	General_works() : Read_Config() {
		int resul = Rozborka_config();
		if (resul == 1) {
			if (Create_file_config() == true)
				cout << "файл конфігурації успішно створений" << endl;
		}
		else {
			if (resul == 2) {
				cout << "ошыбка формата файла конфигурации, проверте файл " << PATCH_CONFIG << endl;
				exit(EXIT_FAILURE);
			}
		}
	}

	void Clear_Base() {
		time_t tmp;
		time(&tmp);
		auto clear = Time_start.begin();
		for (clear; clear != Time_start.end(); clear++) {
			if ((tmp - (*clear).second) >= (5 * this->time_listem_data)) {
				Users.erase((*clear).first);
				Time_start.erase((*clear).first);
			}
		}
	}

	bool Listen_open_connect(string & ip, unsigned short & port, string & protocol) {
		auto res = Start_listem_open_ip.find(ip);
		/*Якщо даний Ір є в базі відкритих Ір, то звіряємо його порт і протокол, по якому буде прослуховування*/
		if (res != Start_listem_open_ip.end()) {
			//time(&time_tmp);
			if (port == 65535 && To_upper_string(protocol) == "TCP") {
				time(&Start_listem_open_ip[ip]);
				return true;
			}
		}
		return false;
	}

	int Start_process() {
		double time1 = 0, time2 = 0;
		time_t Real_time;
		int i = 0;
		unsigned long Size_tmp = 0;
		string read_line, protocol, port_string, ip_address, id_string, firewall_rule;
		ifstream read_log(PATCH_FIREWALL_LOG, ios::in);
		int res_src = 0, res_proto = 0, res_dpt = 0, id_packet = 0;
		Block_firewall bl;
		bl.Function_block();
		unsigned short port = 0;
		bool exit_for = false;
		char * convert_to_string = new char[20];
		/*якщо неможливо відкрити файл логів фаєрвола, то виходим з програми*/
		if (!read_log.is_open()) {
			cout << "Неможу відкрити файл лог фаєрвола, дуже жаль =((((" << endl;
			return EXIT_FAILURE;
		}
		read_log.seekg(0, read_log.end);
		Size_end_file = read_log.tellg();
		Size_tmp = Size_end_file;
		cout << "Start program" << endl;
	ret:
		read_log.seekg(0, read_log.end);
		Size_tmp = read_log.tellg();
		if (Size_end_file == Size_tmp) {
			//_sleep(250);
			cout << "next steep" << endl;
			
			_sleep(250);
			goto ret;
		}
		else {
			//cout << "size end file = " << Size_end_file << " size tmp = " << Size_tmp << endl;
			read_log.seekg(Size_end_file, read_log.beg);
			while (!read_log.eof()) {
				/*Зчитужмо запис з файлу протоколювання*/
				getline(read_log, read_line);
				/*Виділяємо поля заголовка ІР пакету*/
				res_src = read_line.find("SRC");
				res_proto = read_line.find("PROTO");
				res_dpt = read_line.find("DPT");
				/*Якщо поля присутні, значить це ІР пакет*/
				if (res_src != string::npos && res_proto != string::npos && res_dpt != string::npos) {
					protocol = read_line.substr(res_proto + 6, 5);
					protocol = protocol.substr(0, protocol.find(' '));
					port_string = read_line.substr(res_dpt + 4, 5);
					port = atoi(port_string.substr(0, port_string.find(' ')).c_str());
					ip_address = read_line.substr(res_src + 4, 15);
					ip_address = ip_address.substr(0, ip_address.find(' '));
					id_string = read_line.substr(read_line.find("ID") + 3, 9);
					id_packet = atoi(id_string.substr(0, id_string.find(' ')).c_str());
					/*****************************************************************************************
					*    Повністю відділили Ір адрес, протокол, id, і порт на який здійснюється конект       *
					******************************************************************************************/
					/*звіряємо чи не перевірка стану зєднання*/
					if (Listen_open_connect(ip_address, port, protocol) == true) {
						this->Size_end_file += read_line.length() + 1;
						goto ret;
					}
					time(&time_tmp_listen);
					//if ((time_tmp_listen - time_last_clear_base) > 60) {
					//}

					/*якщо база для клієнта пуста, то добавляємо протоколи, порт і Іd*/
					if (Users[ip_address].size() == 0) {
						//cout << "protocol = " << protocol << " port = " << port << endl;
						if (listen_true_combination[0].protocol == protocol && listen_true_combination[0].port == port) {
							time(&Time_start[ip_address]);
							//cout << "Добавив в базу новий запис для нового ІР" << endl;
							Users[ip_address].push_back(Port_And_Protocol_And_ID(protocol, port, id_packet));
						}
					}
					else {
						/*якщо користувач існує вже, і в нього норм база, то звіряємо чи нема такого Ід, і якщо нема, то добавляєно в базу*/
						exit_for = false;
						for (i = 0; i < Users[ip_address].size() && exit == false; i++) {
							if (Users[ip_address][i].ID == id_packet)
								exit_for = true;
						}
						/*Якщо Ідентифікатор не знайдений, то додаємо його до ІР даної бази*/
						if (exit_for == false) {
							time(&Real_time);
							//cout << "попередній ІD не знайдений, добавляємо новий" << endl;
							if ((Real_time - Time_start[ip_address]) <= this->time_listem_data) {
								//cout << "protocol = " << protocol << " port = " << port << endl;
								Users[ip_address].push_back(Port_And_Protocol_And_ID(protocol, port, id_packet));
							}
							else {
								/*Якщо вийшов час попереднього конекту, то вилаляємо стару базу, і записуємо все в нову, і заповнюємо новий час*/
								//cout << "час попереднього вийшов, добавляю заново" << endl;
								Users[ip_address].clear();
								time(&Time_start[ip_address]);
								Users[ip_address].push_back(Port_And_Protocol_And_ID(protocol, port, id_packet));
							}
						}
					}
					/*Якщо розмір однієї із баз рівний, то провіряємо перевіряємо дану бузу */
					if (Users[ip_address].size() == this->listen_true_combination.size() || Users[ip_address].size() == this->close_combination.size()) {
						//cout << "розміри баз рівні" << endl;
						if (True_Combination_Users_open(ip_address) == true) {
							cout << "зв'язок відкритий для " << ip_address << endl;
							for (i = 0; i < this->open_firewall.size(); i++) {
								sprintf(convert_to_string, "%d", this->open_firewall[i].port);
								firewall_rule = "iptables -I INPUT -s " + ip_address + " -p " + this->open_firewall[i].protocol + " --dport " + convert_to_string + " -j ACCEPT";
								//Open_ports_ip.push_back(ip_address);
								//time(&Start_listem_open_ip[ip_address]);
								system(firewall_rule.c_str());
							}
						}
						else {
							/*Якщо комбінація закриття зєднання, то виконуємо закриття зєднання*/
							if (True_Combination_User_close(ip_address) == true) {
								cout << "закрив порт для " << ip_address << endl;
								for (int i = 0; i < this->open_firewall.size(); i++) {
									sprintf(convert_to_string, "%d", this->open_firewall[i].port);
									firewall_rule = "iptables -D INPUT -s " + ip_address + " -p " + this->open_firewall[i].protocol + " --dport " + convert_to_string + " -j ACCEPT";
									system(firewall_rule.c_str());
									//Open_ports_ip.erase(ip_address);
								}
							}
						}
						Users[ip_address].clear();
					}
					this->Size_end_file += read_line.length() + 1;
					//cout << "time = " << time2 - time1 << endl;
					goto ret;
				}
				else {
					this->Size_end_file += read_line.length() + 1;
					//cout << "time = " << time2 - time1 << endl;
					goto ret;
				}
			}
		}
	}
};

int main(int argc, char *argv[])
{
	General_works works;
	works.Start_process();
	/*string test = "hello world";
	cout << test.substr(0, test.find(' ')) << endl;*/
	return 0;
}
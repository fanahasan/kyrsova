#include "algorithms.h"

string To_upper_string(string str) {
	string new_str;
	 // string new_str = str;
	// for (int i = 0; i < new_str.size(); i++) toupper(new_str[i]);
	//  
	new_str.resize(str.size());
	for (int i = 0; i < str.size(); i++) {
		new_str[i] = toupper(str[i]);
	}
	return new_str;
}

string To_lower_string(string str) {
	string new_str;
	new_str.resize(str.size());
	for (int i = 0; i < str.size(); i++) {
		new_str[i] = tolower(str[i]);
	}
	return new_str;
}

#ifndef PASSWORD_LAB_CRACK_H
#define PASSWORD_LAB_CRACK_H

#include <string>

std::string sha256(const std::string &input);
// The inner hash is its lowercase hexadecimal string, followed by the salt.
std::string storedHash(const std::string &password, const std::string &salt);
// Searches a-z at one exact length (1-4); returns an empty string if not found.
std::string crackPassword(const std::string &target, const std::string &salt, int length);

#endif

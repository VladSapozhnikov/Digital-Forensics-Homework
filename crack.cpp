// Password Cracker Demo
// Compile with: g++ -std=c++11 -O2 crack.cpp -o crack
// Run with: ./crack

#include <iostream>
#include <string>
#include <vector>
#include <chrono>

using namespace std;

// A quick SHA256 implementation (truncated version for demo).
typedef unsigned int uint32;

static const uint32 k[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

inline uint32 rotr(uint32 x, int n) {
    return (x >> n) | (x << (32 - n));
}

inline uint32 ch(uint32 x, uint32 y, uint32 z) {
    return (x & y) ^ ((~x) & z);
}

inline uint32 maj(uint32 x, uint32 y, uint32 z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

inline uint32 ep0(uint32 x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

inline uint32 ep1(uint32 x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

inline uint32 sig0(uint32 x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

inline uint32 sig1(uint32 x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

string sha256(const string &input) {
    // Pre-processing
    static const size_t block_size = 64;
    vector<unsigned char> msg(input.begin(), input.end());
    uint64_t bit_len = msg.size() * 8;
    // Append '1' bit
    msg.push_back(0x80);
    // Append 0 bits until length % 512 == 448
    while ((msg.size() * 8) % 512 != 448) {
        msg.push_back(0x00);
    }
    // Append 64-bit length
    for (int i = 7; i >= 0; i--) {
        msg.push_back((bit_len >> (i * 8)) & 0xff);
    }

    // Initial hash values
    uint32 h[8] = {
        0x6a09e667, 0xbb67ae85,
        0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c,
        0x1f83d9ab, 0x5be0cd19
    };

    // Process the message in successive 512-bit chunks
    for (size_t i = 0; i < msg.size(); i += block_size) {
        uint32 w[64];
        for (int j = 0; j < 16; j++) {
            w[j] = (msg[i + j * 4] << 24) |
                   (msg[i + j * 4 + 1] << 16) |
                   (msg[i + j * 4 + 2] << 8) |
                   (msg[i + j * 4 + 3]);
        }
        for (int j = 16; j < 64; j++) {
            w[j] = sig1(w[j - 2]) + w[j - 7] + sig0(w[j - 15]) + w[j - 16];
        }

        uint32 a = h[0];
        uint32 b = h[1];
        uint32 c = h[2];
        uint32 d = h[3];
        uint32 e = h[4];
        uint32 f = h[5];
        uint32 g = h[6];
        uint32 hh = h[7];

        for (int j = 0; j < 64; j++) {
            uint32 temp1 = hh + ep1(e) + ch(e, f, g) + k[j] + w[j];
            uint32 temp2 = ep0(a) + maj(a, b, c);
            hh = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += hh;
    }

    // Produce the final hash value (big-endian)
    char buf[65];
    for (int i = 0; i < 8; i++) {
        sprintf(buf + i * 8, "%08x", h[i]);
    }
    buf[64] = 0;
    return string(buf);
}

// Double-hash with salt: H(H(pw) + salt)
string storedHash(const string &pw, const string &salt) {
    string hpw = sha256(pw);
    return sha256(hpw + salt);
}

// Brute force all-lowercase combos
bool foundPassword = false;
string resultPassword = "";

void bruteForce(const string &target, const string &salt, int length, string current) {
    if (foundPassword) return;
    if ((int)current.size() == length) {
        if (storedHash(current, salt) == target) {
            foundPassword = true;
            resultPassword = current;
        }
        return;
    }
    for (char c = 'a'; c <= 'z'; c++) {
        bruteForce(target, salt, length, current + c);
        if (foundPassword) break;
    }
}

string crackPassword(const string &target, const string &salt, int length) {
    foundPassword = false;
    resultPassword = "";
    bruteForce(target, salt, length, "");
    return resultPassword;
}

int main() {
    // Example usage:
    // 1) Create hashed values for 2 passwords
    string salt = "abcdefghijklmnop"; // 16-char salt
    string pw1 = "test"; // 4 letters
    string pw2 = "abcd"; // another 4 letters

    string hash1 = storedHash(pw1, salt);
    string hash2 = storedHash(pw2, salt);

    // 2) Time the crack for each
    auto start = chrono::steady_clock::now();
    string found1 = crackPassword(hash1, salt, pw1.size());
    auto end = chrono::steady_clock::now();
    cout << "Cracked 1: " << found1 << " in "
         << chrono::duration_cast<chrono::milliseconds>(end - start).count()
         << " ms" << endl;

    start = chrono::steady_clock::now();
    string found2 = crackPassword(hash2, salt, pw2.size());
    end = chrono::steady_clock::now();
    cout << "Cracked 2: " << found2 << " in "
         << chrono::duration_cast<chrono::milliseconds>(end - start).count()
         << " ms" << endl;
    return 0;
}

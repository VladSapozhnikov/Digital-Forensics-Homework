#include "../crack.h"
#include <iostream>
#include <string>

static int failures = 0;

static void check(bool passed, const char *name) {
    if (!passed) {
        std::cerr << "FAIL: " << name << '\n';
        ++failures;
    }
}

int main() {
    check(sha256("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "empty input SHA-256");
    check(sha256("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
          "abc SHA-256");
    check(sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") ==
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
          "multiple block SHA-256");
    check(sha256(std::string(1, '\xff')) ==
          "a8100ae6aa1940d0b663bb31cd466142ebbdbd5187131b92d93818987832eb89",
          "high-bit byte SHA-256");
    check(storedHash("test", "salt-one") != storedHash("test", "salt-two"),
          "changing salt changes stored hash");
    const std::string salt = "synthetic-salt";
    check(crackPassword(storedHash("ab", salt), salt, 2) == "ab", "recover synthetic password");
    check(crackPassword(storedHash("z", salt), salt, 1) == "z", "reset search state");
    check(crackPassword(storedHash("A", salt), salt, 1).empty(), "uppercase outside search space");
    check(crackPassword(storedHash("a", salt), "different-salt", 1).empty(), "wrong salt");
    check(crackPassword(storedHash("a", salt), salt, 0).empty(), "reject zero length");
    check(crackPassword(storedHash("a", salt), salt, 5).empty(), "reject excessive length");
    if (failures) return 1;
    std::cout << "All 11 password-lab checks passed.\n";
    return 0;
}

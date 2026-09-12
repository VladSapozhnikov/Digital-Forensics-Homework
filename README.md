# Password Hashing and Brute-Force Lab

A small C++ learning project that recovers two synthetic four-letter passwords by enumerating lowercase candidates. It began as digital forensics coursework. The maintained version includes build instructions, correctness checks, and an explanation of what the demonstration can and cannot show.

## What the demonstration shows

The program creates hashes for the built-in passwords `test` and `abcd`, then searches for each password in alphabetical order. It uses the fixed example salt `abcdefghijklmnop`.

For each candidate, it computes:

```text
inner = SHA256(password), represented as a lowercase hexadecimal string
stored = SHA256(inner + salt)
```

The program compares the candidate's stored value with the synthetic target. It does not decrypt a hash. There are **26^4 = 456,976** possible four-letter lowercase strings; the search stops when it finds a match.

`abcd` appears much earlier than `test` in this ordering, so it generally takes fewer guesses. The time difference is a property of this search order and this toy setup, not a general password-strength score.

## Build and run

Requires a C++11 compiler. Make is optional; no external libraries or datasets are needed.

### Linux, macOS, or a Linux terminal on Windows

```bash
git clone https://github.com/VladSapozhnikov/Digital-Forensics-Homework.git
cd Digital-Forensics-Homework
make
./crack
```

Without Make:

```bash
g++ -std=c++11 -Wall -Wextra -Wpedantic -O2 crack.cpp -o crack
./crack
```

### Windows PowerShell with g++ already installed

From the repository folder:

```powershell
g++ -std=c++11 -Wall -Wextra -Wpedantic -O2 crack.cpp -o crack.exe
.\crack.exe
```

If `g++` is not available in PowerShell, use a Linux environment with a compiler, such as WSL or an SSH session. The build and test results below were verified on Linux; native Windows and macOS have not been tested.

## Example output

One measured run in the Linux test environment produced:

```text
Cracked 1: test in 508 ms
Cracked 2: abcd in 1 ms
```

Your timings will vary with the machine, compiler, and load. The recovered passwords should match. A run exits with an error if either built-in example is not recovered correctly.

## Run the checks

```bash
make test
```

All **11 checks passed on Linux**, followed by a successful recovery of both built-in examples. Checks cover SHA-256 outputs for empty, short, multi-block, and high-bit inputs; changed salts; successful recovery; search-state reset; and inputs outside the supported search space. Both builds completed with `-Wall -Wextra -Wpedantic` and no warnings.

- [`crack.cpp`](crack.cpp): hashing, candidate enumeration, and timed demo.
- [`crack.h`](crack.h): declarations used by the checks.
- [`tests/test_crack.cpp`](tests/test_crack.cpp): deterministic correctness checks.
- [`Makefile`](Makefile): build, test, and clean commands.

## Findings and limits

- A salt changes the stored value, but it does not prevent trying candidates against one known hash and salt. This demo deliberately reuses one fixed salt.
- Repeating a fast hash twice is still inexpensive in this small search space. Real password storage requires a dedicated password-hashing scheme with an appropriate work factor; see [OWASP's password-storage guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
- The search only covers `a` through `z` at one known length, limited to 1-4 characters. It does not search arbitrary passwords or estimate real-world cracking times.
- The SHA-256 code is educational, with sample correctness checks. It is not an audited cryptographic library.
- The program operates on its own built-in synthetic data. It does not connect to services, ingest credential dumps, or analyze forensic disk images.

The portfolio cleanup also replaced platform-dependent integer/formatting assumptions, bounded the demo search, and removed the tracked executable. Build your own executable from the source above.

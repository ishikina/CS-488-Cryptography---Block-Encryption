#include <iostream>
#include <fstream>
#include <cstring>
#include <bitset>
#include <cstdint>
#include <sstream>

using namespace std;

const int MAX = 1000; //Input size
extern bitset<8> sub_keys[16][12];
extern uint8_t subkeys[16][12];
extern uint8_t ftable[256];
extern uint64_t input[MAX];
class psu_crypt;
extern psu_crypt cipherblocks[MAX];

struct cipherblock
{
	cipherblock();
	~cipherblock();
	cipherblock(uint64_t plaintext, uint64_t key);
	
	uint16_t r0;
	uint16_t r1;
	uint16_t r2;
	uint16_t r3;
	
	uint32_t f0;
	uint32_t f1;
	void print();
};

class psu_crypt
{
	public:

	psu_crypt();
	psu_crypt(uint64_t plaintext, uint64_t key);
	~psu_crypt();

  void des(uint64_t plaintext, uint64_t key, int encrypt);
	void print();	
	uint64_t text;
	
	protected:
	
	void f_function(cipherblock & block, int round, int encrypt);
	uint16_t g_permutation(uint16_t r, int round, int subkey, int encrypt);
  uint8_t f_table(uint8_t inside, uint8_t subkey, uint8_t outside);

	private:

	cipherblock rounds[16];
};

string hex_to_binary(string input);
string file_to_string(string file);
void input_to_hex(string plaintext);
void convert_hex(string ciphertext);
void subkey_convert();
void psu_crypt_to_file(psu_crypt * blocks, string file, int encrypt);
void rotate_key(string * key);	
void create_subkeys(string key);
void encrypt(string plaintext_file, string key_file, string ciphertext_file);
void decrypt(string ciphertext_file, string key_file, string plaintext_file);
void display_subkeys(int encrypt);



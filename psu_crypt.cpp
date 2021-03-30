#include "program1.h"

bitset<8> sub_keys[16][12];
uint8_t subkeys[16][12];
uint64_t input[MAX];
psu_crypt cipherblocks[MAX];

uint8_t ftable[] =
{0xa3,0xd7,0x09,0x83,0xf8,0x48,0xf6,0xf4,0xb3, 0x21,0x15,0x78,0x99,0xb1,0xaf,0xf9,
0xe7,0x2d,0x4d,0x8a,0xce,0x4c,0xca,0x2e,0x52,0x95,0xd9,0x1e,0x4e,0x38,0x44,0x28,
0x0a,0xdf,0x02,0xa0,0x17,0xf1,0x60,0x68,0x12,0xb7,0x7a,0xc3,0xe9,0xfa,0x3d,0x53,
0x96,0x84,0x6b,0xba,0xf2,0x63,0x9a,0x19,0x7c,0xae,0xe5,0xf5,0xf7,0x16,0x6a,0xa2,
0x39,0xb6,0x7b,0x0f,0xc1,0x93,0x81,0x1b,0xee,0xb4,0x1a,0xea,0xd0,0x91,0x2f,0xb8,
0x55,0xb9,0xda,0x85,0x3f,0x41,0xbf,0xe0,0x5a,0x58,0x80,0x5f,0x66,0x0b,0xd8,0x90,
0x35,0xd5,0xc0,0xa7,0x33,0x06,0x65,0x69,0x45,0x00,0x94,0x56,0x6d,0x98,0x9b,0x76, 
0x97,0xfc,0xb2,0xc2,0xb0,0xfe,0xdb,0x20,0xe1,0xeb,0xd6,0xe4,0xdd,0x47,0x4a,0x1d,
0x42,0xed,0x9e,0x6e,0x49,0x3c,0xcd,0x43,0x27,0xd2,0x07,0xd4,0xde,0xc7,0x67,0x18,
0x89,0xcb,0x30,0x1f,0x8d,0xc6,0x8f,0xaa,0xc8,0x74,0xdc,0xc9,0x5d,0x5c,0x31,0xa4,
0x70,0x88,0x61,0x2c,0x9f,0x0d,0x2b,0x87,0x50,0x82,0x54,0x64,0x26,0x7d,0x03,0x40,
0x34,0x4b,0x1c,0x73,0xd1,0xc4,0xfd,0x3b,0xcc,0xfb,0x7f,0xab,0xe6,0x3e,0x5b,0xa5,
0xad,0x04,0x23,0x9c,0x14,0x51,0x22,0xf0,0x29,0x79,0x71,0x7e,0xff,0x8c,0x0e,0xe2,
0x0c,0xef,0xbc,0x72,0x75,0x6f,0x37,0xa1,0xec,0xd3,0x8e,0x62,0x8b,0x86,0x10,0xe8,
0x08,0x77,0x11,0xbe,0x92,0x4f,0x24,0xc5,0x32,0x36,0x9d,0xcf,0xf3,0xa6,0xbb,0xac,
0x5e,0x6c,0xa9,0x13,0x57,0x25,0xb5,0xe3,0xbd,0xa8,0x3a,0x01,0x05,0x59,0x2a,0x46};

//cipherblock constructor
cipherblock::cipherblock()
{
	this->r0 = 0;
	this->r1 = 0;
	this->r2 = 0;
	this->r3 = 0;
	this->f0 = 0;
	this->f1 = 0;
}

//cipherblock constructor w/ whitening
cipherblock::cipherblock(uint64_t plaintext, uint64_t key)
{
	this->r0 = (plaintext >> 48) ^ (key >> 48);
	this->r1 = (plaintext >> 32) ^ (key >> 32);
	this->r2 = (plaintext >> 16) ^ (key >> 16);
	this->r3 = (plaintext ^ key);
	this->f0 = 0;
	this->f1 = 0;
}

//cipherblock destructor
cipherblock::~cipherblock()
{}

//psu_crypt constructor
psu_crypt::psu_crypt()
{
	for(int i = 0; i < 16; ++i)
		this->rounds[i] = cipherblock();
	uint64_t text = 0;
}

//psu_crypt constructor w/ whitening
psu_crypt::psu_crypt(uint64_t plaintext, uint64_t key)
{
	this->rounds[0] = cipherblock(plaintext, key);
	for(int i = 1; i < 16; ++i)
		this->rounds[i] = cipherblock();
	uint64_t text = 0;
}

//psu_crypt destructor
psu_crypt::~psu_crypt()
{}

//DES process
void psu_crypt::des(uint64_t plaintext, uint64_t key, int encrypt)
{
	this->rounds[0] = cipherblock(plaintext, key);
	for(int i = 1; i < 16; ++i)
		this->rounds[i] = cipherblock();

	for(int i = 0; i < 16; ++i)	
	{	
		f_function(rounds[i], i, encrypt);
		this->rounds[i+1].r0 = this->rounds[i].r2 ^ this->rounds[i].f0;
		this->rounds[i+1].r1 = this->rounds[i].r3 ^ this->rounds[i].f1;
		this->rounds[i+1].r2 = this->rounds[i].r0;
		this->rounds[i+1].r3 = this->rounds[i].r1;
	}
	uint16_t c0 = rounds[16].r2 ^ (key >> 48);
	uint16_t c1 = rounds[16].r3 ^ (key >> 32);
	uint16_t c2 = rounds[16].r0 ^ (key >> 16);
	uint16_t c3 = rounds[16].r1 ^ key;
	
	uint32_t first = ((uint32_t)c0 << 16) | c1;
	uint32_t second = ((uint32_t)c2 << 16) | c3;
	this->text = ((uint64_t)first << 32) | second;
}

//F Function
void psu_crypt::f_function(cipherblock & block, int round, int encrypt)
{
	//Encryption
	if(encrypt)	
	{	
		uint16_t t0 = g_permutation(block.r0, round, 0, encrypt);
		uint16_t t1 = g_permutation(block.r1, round, 4, encrypt);
		block.f0 = (t0 + (2 * t1) + (256U * subkeys[round][8] + subkeys[round][9])) % 65536;
		block.f1 = ((2 * t0) + t1 + (256U * subkeys[round][10] + subkeys[round][11])) % 65536;
	}	
	
	//Decryption	
	else
	{
		uint16_t t0 = g_permutation(block.r0, round, 0, encrypt);
		uint16_t t1 = g_permutation(block.r1, round, 4, encrypt);
		block.f0 = (t0 + (2 * t1) + (256U * subkeys[15 - round][8] + subkeys[15 - round][9])) % 65536;
		block.f1 = ((2 * t0) + t1 + (256U * subkeys[15 - round][10] + subkeys[15 - round][11])) % 65536;
	}	
}

//G Permutation
uint16_t psu_crypt::g_permutation(uint16_t r, int round, int subkey, int encrypt)
{
	//Encryption	
	if(encrypt)	
	{	
		uint8_t g1 = r >> 8;
		uint8_t g2 = r;
		uint8_t g3 = f_table(g2, subkeys[round][subkey], g1);
		uint8_t g4 = f_table(g3, subkeys[round][subkey + 1], g2);
		uint8_t g5 = f_table(g4, subkeys[round][subkey + 2], g3);
		uint8_t g6 = f_table(g5, subkeys[round][subkey + 3], g4);
	
		return 256U * g5 + g6;	
	}
	
	//Decryption	
	else	
	{	
		uint8_t g1 = r >> 8;
		uint8_t g2 = r;
		uint8_t g3 = f_table(g2, subkeys[15 - round][subkey], g1);
		uint8_t g4 = f_table(g3, subkeys[15 - round][subkey + 1], g2);
		uint8_t g5 = f_table(g4, subkeys[15 - round][subkey + 2], g3);
		uint8_t g6 = f_table(g5, subkeys[15 - round][subkey + 3], g4);
	
		return 256U * g5 + g6;	
	}
}

//F Table 
uint8_t psu_crypt::f_table(uint8_t inside, uint8_t subkey, uint8_t outside)
{
	uint8_t skipjack = inside ^ subkey;	
	int row = skipjack >> 4;
	int column = skipjack & 15;
	
	return ftable[row * 16 + column] ^ outside;
}

//Printing results to file
void psu_crypt_to_file(psu_crypt * blocks, string file, int encrypt)
{
	ofstream output_file;
	output_file.open(file);
	char temp;
	
	while((blocks + 1)->text)
	{
		//Ecryption	
		if(encrypt)
			output_file << hex << blocks->text;
	
		//Decryption	
		else
		{
			bitset<64> hex1(blocks->text);	
			stringstream hex2;
			hex2 << hex << hex1.to_ulong();	
			string hex3 = hex2.str();	
			string ascii;	
			for(int i = 0; i < hex3.length(); i += 2)
			{
				string part = hex3.substr(i, 2);
				char ch = stoul(part, nullptr, 16);
				ascii +=ch;
			}
			output_file << ascii;	
		}	
		++blocks;
	}
	output_file.close();	
}

//Converting subkeys from bitset to uint_8t hex
void subkey_convert()
{
	for(int i = 0; i < 16; ++i)
	{
		for(int j = 0; j < 12; ++j)
			subkeys[i][j] = (uint8_t)sub_keys[i][j].to_ulong();
	}
}

//Converting hex string to binary string
//-------CODE_DERIVED_FROM_GEEKSFORGEEKS---------//	
string hex_to_binary(string input)
{
	string binary_output;
	for(int i = 0; i < 16; i++) 
 	{ 
		switch (input[i]) 
		{
      case '0':
			  binary_output += "0000";
          break;
      case '1':
				binary_output += "0001";
          break;
      case '2':
				binary_output += "0010";
          break;
      case '3':
				binary_output += "0011";
          break;
      case '4':
				binary_output += "0100";
          break;
      case '5':
				binary_output += "0101";
          break;
      case '6':
				binary_output += "0110";
          break;
      case '7':
				binary_output += "0111";
          break;
      case '8':
				binary_output += "1000";
          break;
      case '9':
				binary_output += "1001";
          break;
      case 'A':
      case 'a':
				binary_output += "1010";
          break;
      case 'B':
      case 'b':
				binary_output += "1011";
          break;
      case 'C':
      case 'c':
				binary_output += "1100";
          break;
      case 'D':
      case 'd':
				binary_output += "1101";
          break;
      case 'E':
      case 'e':
				binary_output += "1110";
          break;
      case 'F':
      case 'f':
				binary_output += "1111";
          break;
      default:
          cout << "\nInvalid hexadecimal digit " << input[i];
    }
	}
	return binary_output;
}
//--------------------------------//

//Rotating key
void rotate_key(string * key)
{
	char temp = (*key)[0];
	for(int i = 0; i < 63; ++i)
		(*key)[i] = (*key)[i + 1];
	(*key)[63] = temp;
}

//Key schedule
void create_subkeys(string key)
{
	int key_counter = 0;	
	for(int i = 0; i < 16; ++i)
	{
		key_counter = 0;	
		if(i % 2 == 0)	
		{	
			rotate_key(&key);
			sub_keys[i][key_counter] = bitset<8>(key.substr(56, 63));

			++key_counter;	
			rotate_key(&key);
			sub_keys[i][key_counter] = bitset<8>(key.substr(48, 55));
	
			++key_counter;	
			rotate_key(&key);
			sub_keys[i][key_counter] = bitset<8>(key.substr(40, 47));
		
			++key_counter;	
			rotate_key(&key);
			sub_keys[i][key_counter] = bitset<8>(key.substr(32, 39));
		
			++key_counter;	
			rotate_key(&key);
			sub_keys[i][key_counter] = bitset<8>(key.substr(56, 63));

			++key_counter;	
			rotate_key(&key);
			sub_keys[i][key_counter] = bitset<8>(key.substr(48, 55));
	
			++key_counter;	
			rotate_key(&key);
			sub_keys[i][key_counter] = bitset<8>(key.substr(40, 47));
		
			++key_counter;	
			rotate_key(&key);
			sub_keys[i][key_counter] = bitset<8>(key.substr(32, 39));
		
			++key_counter;	
			rotate_key(&key);
			sub_keys[i][key_counter] = bitset<8>(key.substr(56, 63));

			++key_counter;	
			rotate_key(&key);
			sub_keys[i][key_counter] = bitset<8>(key.substr(48, 55));
	
			++key_counter;	
			rotate_key(&key);
			sub_keys[i][key_counter] = bitset<8>(key.substr(40, 47));
		
			++key_counter;	
			rotate_key(&key);
			sub_keys[i][key_counter] = bitset<8>(key.substr(32, 39));
		}	

		else
		{
			rotate_key(&key);
			sub_keys[i][key_counter] = bitset<8>(key.substr(24, 31));

			++key_counter;	
			rotate_key(&key);
			sub_keys[i][key_counter] = bitset<8>(key.substr(16, 23));

			++key_counter;	
			rotate_key(&key);
			sub_keys[i][key_counter] = bitset<8>(key.substr(8, 15));
			
			++key_counter;	
			rotate_key(&key);
			sub_keys[i][key_counter] = bitset<8>(key.substr(0, 8));

			++key_counter;	
			rotate_key(&key);
			sub_keys[i][key_counter] = bitset<8>(key.substr(24, 31));

			++key_counter;	
			rotate_key(&key);
			sub_keys[i][key_counter] = bitset<8>(key.substr(16, 23));

			++key_counter;	
			rotate_key(&key);
			sub_keys[i][key_counter] = bitset<8>(key.substr(8, 15));
			
			++key_counter;	
			rotate_key(&key);
			sub_keys[i][key_counter] = bitset<8>(key.substr(0, 8));

			++key_counter;	
			rotate_key(&key);
			sub_keys[i][key_counter] = bitset<8>(key.substr(24, 31));

			++key_counter;	
			rotate_key(&key);
			sub_keys[i][key_counter] = bitset<8>(key.substr(16, 23));

			++key_counter;	
			rotate_key(&key);
			sub_keys[i][key_counter] = bitset<8>(key.substr(8, 15));
			
			++key_counter;	
			rotate_key(&key);
			sub_keys[i][key_counter] = bitset<8>(key.substr(0, 8));
		}	
	}
}

//Print subkeys
void display_subkeys(int encrypt)
{
	//Encryption	
	if(encrypt)	
	{	
		for(int i = 0; i < 16; ++i)
		{
			for(int j = 0; j < 12; ++j)
				cout << "0x" << static_cast<int>(subkeys[i][j]) << "  ";
			cout << endl;	
		}
	}
	
	//Decryption
	else
	{
		for(int i = 15; i > -1; --i)
		{
			for(int j = 0; j < 12; ++j)
				cout << "0x" << static_cast<int>(subkeys[i][j]) << "  ";
			cout << endl;	
		}	
	}
}

//Converting file input to string
string file_to_string(string file)
{
  string file_string;	
	string text;
	
	ifstream read_file(file);
	if(read_file.is_open())	
	{
		while(getline(read_file, text))
		{
			file_string = text;
		}
		read_file.close();	
	}

	return file_string;
}



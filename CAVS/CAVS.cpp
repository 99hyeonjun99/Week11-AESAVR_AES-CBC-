
// CAVS.cpp : 이 파일에는 'main' 함수가 포함됩니다. 거기서 프로그램 실행이 시작되고 종료됩니다.
//

#include <iostream>
#include "AES8.h"
#include "AES32.h"

using namespace std;

bool isHex(char ch) {
	return((ch >= '0') && (ch<='9')) || ((ch >= 'a') && (ch <= 'f')) || ((ch >= 'A') && (ch <= 'F'));
}

//'8' -> 8, 'd' ->13 'g' -> error
// 입력 ch: {0, 1, ... , 9, A, ... ,F, a, ... ,f}
byte Hex2Digit(char ch) {
	if (!isHex(ch)) {
		cout << ch << "is not a hex value." << endl;
		return -1; //의미없는 값
	}
	if ((ch >= '0') && (ch <= '9')) {
		return ch - '0';
	}
	else if ((ch >= 'A') && (ch <= 'F')) {
		return ch - 'A' + 10;
	}
	else if ((ch >= 'a') && (ch <= 'f')) {
		return ch - 'a' + 10;
	}

	cout << "unknown error." << endl;
	return -1;
}

// "8d" --> 8d
byte Hex2Byte(const char h[2]) {
	byte upper, lower;
	upper = h[0];
	lower = h[1];
	if ((!isHex(upper)) || (!isHex(lower))) {
		cout << "Hex error" << endl;
		return -1;
	}
	return Hex2Digit(upper) * 16 + Hex2Digit(lower); // ??? '8'*16 + 'd'
}

//" 8d2e60365f17c7df1040d7501b4a7b5a"-->{8d, 2e, ... , 5a}
void Hex2Array(const char hex_str[], int hex_len, byte barr[]) {
	char h[2];
	byte b_value;
	for (int i = 0; i < hex_len / 2; i++) {
		h[0] = hex_str[2 * i];
		h[1] = hex_str[2 * i + 1];
		b_value = Hex2Byte(h);
		barr[i] = b_value;
	}
}

void print_b_array(byte b_arr[], int len, const char *pStr=nullptr) {
	if (pStr != nullptr) {
		printf("%s = ", pStr);
	}
	for (int i = 0; i < len; i++) {
		printf("%02x ", b_arr[i]);
	}
	printf("\n");
}

void hex_string_test() {
	const char* hex_string = "8d2e60365f17c7df1040d7501b4a7b5a";
	byte b[16];
	Hex2Array(hex_string, 32, b);
	print_b_array(b, 16, "KEY");
}

void copy_b_array(byte src[], int len, byte dest[]) {
	for (int i = 0; i < len; i++) {
		dest[i] = src[i];
	}
}

void xor_b_array(byte data[], int len, byte xor_arr[]) {
	for (int i = 0; i < len; i++) {
		data[i] ^= xor_arr[i];
	}
}

//-----------------------------------------------------------------
void MCT_ECB() {
	const char* hex_key = "8d2e60365f17c7df1040d7501b4a7b5a";
	const char* hex_pt = "59b5088e6dadc3ad5f27a460872d5929";
	byte key[16], pt[16], ct[16];
	u32 rk32[11][4];

	Hex2Array(hex_key, 32, key);
	Hex2Array(hex_pt, 32, pt);

	for (int i = 0; i < 3; i++) {
		print_b_array(key, 16, "KEY");
		print_b_array(pt, 16, "PT");
		for (int j = 0; j < 1000; j++) {
			AES32_Enc_KeySchedule(key, rk32);
			AES32_Encrypt(pt, rk32, ct);
			copy_b_array(ct, 16, pt);
		}
		print_b_array(ct, 16, "CT");

		xor_b_array(key, 16, ct);
		copy_b_array(ct, 16, pt);
		printf("\n");

	}

}

void MCT_CBC() {
	const char* hex_key = "9dc2c84a37850c11699818605f47958c";
	const char* hex_iv = "256953b2feab2a04ae0180d8335bbed6";
	const char* hex_pt = "2e586692e647f5028ec6fa47a55a2aab";
	byte key[16], pt[16], iv[16],ct[16], prev_ct[16];
	u32 rk32[11][4];

	Hex2Array(hex_key, 32, key);
	Hex2Array(hex_iv, 32, iv);
	Hex2Array(hex_pt, 32, pt);

	for (int i = 0; i < 3; i++) {
		print_b_array(key, 16, "KEY");
		print_b_array(iv, 16, "IV");
		print_b_array(pt, 16, "PT");

		for (int j = 0; j < 1000; j++) {
			AES32_Enc_KeySchedule(key, rk32);
			if (j == 0) {
				xor_b_array(pt, 16, iv);
				AES32_Encrypt(pt, rk32, ct);
				copy_b_array(iv, 16, pt);
			}
			else {
				copy_b_array(ct, 16, prev_ct);
				xor_b_array(pt, 16, prev_ct);
				AES32_Encrypt(pt, rk32, ct);
				copy_b_array(prev_ct, 16, pt);
			}
		}
		print_b_array(ct, 16, "CT");
		xor_b_array(key, 16, ct);
		copy_b_array(ct, 16, iv);
		printf("\n");
	}
}

int main()
{
	//hex_string_test();
	//MCT_ECB();
	MCT_CBC();
}


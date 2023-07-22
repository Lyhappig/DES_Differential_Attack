#ifndef DES_DIFFERENTIAL_ATTACK_THREE_ROUNDS_THREE_ATTACK_HPP_
#define DES_DIFFERENTIAL_ATTACK_THREE_ROUNDS_THREE_ATTACK_HPP_
#include <iostream>
#include <cstdio>
#include <string>
#include <map>
#include <vector>
#include <algorithm>
#include "des.hpp"
using namespace std;

/**
 * 明文对的个数
 */
#define NUM 3

#define PRINT_KEY
#define PRINT_CYPHER
//#define PRINT_DELTA
//#define PRINT_J

string sp[NUM][2] = {
    {
        "748502CD38451097",
        "3874756438451097"
    },
    {
        "486911026ACDFF31",
        "375BD31F6ACDFF31"
    },
    {
        "357418DA013FEC86",
        "12549847013FEC86"
    }
};

string skey = "1A624C89520DEC46";

/**
 * 0-15与十六进制字符的映射表
 */
map<char, bitset<4>> mp;

/**
 * 8个S盒的差分分布表
 */
vector<int> s_xor[8][64][16];

/**
 * 打印前3轮的轮密钥
 */
void print_rounds_key(DES_KEY *desKey, int rounds) {
    for(int i = 0; i < rounds; i++) {
        printf("round %d key: ", i + 1);
        for(int j = 1; j <= 48; j += 8) {
            uint8 now = 0;
            for(int k = j; k < j + 8; k++) {
                now <<= 1;
                now |= desKey->rd_key[i][k];
            }
            printf("%02X", now);
        }
        cout << "\t";
        string bits = "";
        for(int j = 1; j <= 48; j += 6) {
            for(int k = j; k < j + 6; k++) {
                bits += '0' + desKey->rd_key[i][k];
            }
            bits += " ";
        }
        cout << bits << "\n";
    }
}


/**
 * 打印n个比特为byte输出
 * @param p
 * @param n
 */
void bits_print_bytes(const bit *p, int n) {
    int t = 0;
    for (int i = 1; i <= n; i++) {
        t = (t << 1) | p[i];
        if (i % 8 == 0) {
            printf("%02X", t);
            t = 0;
        }
    }
    puts("");
}


/**
 * 打印长度为n的比特流
 * @param p
 * @param n
 */
void print_bits(bit *p, int n, bool flag) {
    for(int i = 1; i <= n; i++) {
        cout << p[i];
        if(i % 4 == 0) {
            cout << " ";
        }
        if(i == n / 2 && flag) {
            cout << "|| ";
        }
    }
    cout << "\n";
}

/**
 * 打印S盒的差分分布表
 * @param id
 */
void print_s_xor(int id) {
    bitset<6> in;
    bitset<4> out;
    for(int i = 0; i < 64; i++) {
        for(int j = 0; j < 16; j++) {
            in = bitset<6>(i);
            cout << in << " ";
            out = bitset<4>(j);
            cout << out << " ";
            printf("(%d): ", (int)s_xor[id][i][j].size());
            for(auto &k: s_xor[id][i][j]) {
                in = bitset<6>(k);
                cout << in << " ";
            }
            puts("");
        }
    }
}

/**
 * 初始化十六进制字符和对应的4个比特的映射表
 */
void init_map() {
    for (int i = 0; i < 10; i++) {
        mp['0' + i] = bitset<4>(i);
    }
    mp['A'] = bitset<4>(10);
    mp['B'] = bitset<4>(11);
    mp['C'] = bitset<4>(12);
    mp['D'] = bitset<4>(13);
    mp['E'] = bitset<4>(14);
    mp['F'] = bitset<4>(15);
}


/**
 * 根据给定的密钥十六进制字符串，初始化轮密钥
 * @param desKey
 */
void init_key(DES_KEY *desKey) {
    bitset<64> bk;
    for (int i = 0; i < skey.size(); i++) {
        bitset<4> t = mp[skey[i]];
        bk <<= 4;
        for (int j = 0; j < 4; j++) bk[j] = t[j];
    }
    bit K[65];
    for (int i = 1, j = 63; i <= 64; i++, j--) {
        K[i] = bk[j];
    }
    set_key(K, desKey);
#ifdef PRINT_KEY
    cout << "main key is: " << skey << " " << bk << "\n";
    print_rounds_key(desKey, 3);
#endif
}

/**
 * 初始化所有S盒的差分分布表
 */
void init_s_xor() {
    for(int index = 0; index < 8; index++) {
        for(int delta = 0; delta < 64; delta++) {
            for(int i = 0, j, k; i < 64; i++) {
                j = delta ^ i;
                k = get_sbox(i, index) ^ get_sbox(j, index);
                s_xor[index][delta][k].push_back(i);
            }
        }
    }
#ifdef PRINT_S_XOR
    print_s_xor(0);
#endif
}

#endif //DES_DIFFERENTIAL_ATTACK_THREE_ROUNDS_THREE_ATTACK_HPP_

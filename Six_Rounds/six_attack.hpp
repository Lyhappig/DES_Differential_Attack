#ifndef DES_DIFFERENTIAL_ATTACK_SIX_ROUNDS_SIX_ATTACK_HPP_
#define DES_DIFFERENTIAL_ATTACK_SIX_ROUNDS_SIX_ATTACK_HPP_
#include <set>
#include <map>
#include <cstdio>
#include <vector>
#include <iostream>
#include <algorithm>
#include "des.hpp"
using namespace std;

//#define PRINT_S_XOR
#define PRINT_PLAIN
#define PRINT_INACTIVE
#define PRINT_KEY

#define ATK_ROUNDS 6
#define NUM 120

uint64 key = 0x34E9E71A20756231ULL;
set<int> is_inactive;
vector<int> s_xor[8][64][16];

struct Node {
  bitset<64> mask[8];

  Node() {
      for(int i = 0; i < 8; i++) {
          mask[i].reset();
      }
  }

  bool has_edge(const Node &p) {
      for(int i = 0; i < 8; i++) {
          if(!is_inactive.count(i)) continue;
          bitset<64> t = mask[i] & p.mask[i];
          if(t.to_ullong() == 0) return false;
      }
      return true;
  }
};

struct Clique {
  set<int> idx;
  Node root;

  Clique() {
      idx.clear();
  }

  void add_node(Node &p, int id) {
      idx.insert(id);
      for(int i = 0; i < 8; i++) {
          if(!is_inactive.count(i)) continue;
          root.mask[i] &= p.mask[i];
      }
  }
};

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
 * uint32转化为比特
 * @param in
 * @param out
 */
void uint32_bits(uint32 in, bit *out) {
    for(int i = 1; i <= 32; i++) {
        out[i] = (in >> (32 - i)) & 1;
    }
}

/**
 * uint64转化为比特
 * @param in
 * @param out
 */
void uint64_bits(uint64 in, bit *out) {
    for(int i = 1; i <= 64; i++) {
        out[i] = (in >> (64 - i)) & 1;
    }
}

/**
 * 打印前6轮的轮密钥
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
 * 找到最大团的第i个密钥比特的值
 * @param q
 * @param i
 * @return
 */
int find_partial_key(Clique &q, int i) {
    for(int j = 0; j < 64; j++) {
        if(q.root.mask[i][j]) {
            return j;
        }
    }
    return -1;
}


/**
 * 根据给定的密钥，初始化轮密钥
 * @param desKey
 */
void init_key(DES_KEY *desKey) {
    bitset<64> bk(key);
    bit K[65];
    for (int i = 1, j = 63; i <= 64; i++, j--) {
        K[i] = bk[j];
    }
    set_key(K, desKey);
#ifdef PRINT_KEY
    printf("main key is: %llX ", key);
    cout << bk << "\n";
    print_rounds_key(desKey, 6);
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


#endif //DES_DIFFERENTIAL_ATTACK_SIX_ROUNDS_SIX_ATTACK_HPP_

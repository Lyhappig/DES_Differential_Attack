#include <iostream>
#include <map>
#include <set>
#include <algorithm>
#include <vector>
#include "des.hpp"
using namespace std;

/**
 * 测试第一个S盒的差分分布表
 */
void test_stable() {
    int dx = '\x34', dy = '\x03';
    map<pair<int, int>, bool> mp;
    vector<pair<int, int>> ans;
    for (int i = 0; i < 64; i++) {
        int j = i ^ dx;
        if ((get_sbox(i, 0) ^ get_sbox(j, 0)) == dy) {
            if (!mp.count({i, j}) && !mp.count({j, i})) {
                mp[{i, j}] = 1;
                mp[{j, i}] = 1;
                ans.push_back({min(i, j), max(i, j)});
            }
        }
    }
    int x = '\x21';
    for (auto &val : ans) {
        printf("%02X,%02X ", val.first ^ x, val.second ^ x);
    }
    puts("");
}

/**
 * 测试加密
 */
void test_crypt() {
    // '0' --- 48
    int sp[8] = {'\x49', '\x50', '\x51', '\x52', '\x53', '\x54', '\x55', '\x56'};
    int sk[8] = {'\x49', '\x50', '\x51', '\x52', '\x53', '\x54', '\x55', '\x56'};
    bit k[64 + 1], p[64 + 1], c[64 + 1];
    DES_KEY desKey;
    for (int i = 1; i <= 64; i += 8) {
        int x = sk[i / 8];
        for (int j = i; j < i + 8; j++) {
            k[j] = (x >> (7 - j + i) & 1);
        }
    }
    set_key(k, &desKey);
    for (int i = 1; i <= 64; i += 8) {
        int x = sp[i / 8];
        for (int j = i; j < i + 8; j++) {
            p[j] = (x >> (7 - j + i) & 1);
        }
    }
    des_crypt(p, c, &desKey, ENCRYPT);
    int t = 0;
    for (int i = 1; i <= 64; i++) {
        t = (t << 1) | c[i];
        if (i % 8 == 0) {
            printf("%02x", t);
            t = 0;
        }
    }
    puts("");
    // c8b0477de75aeb5c
}

void get_bits(uint32 &delta, bit *x) {
    bitset<32> b(delta);
    for (int i = 31, j = 1; i >= 0; i--, j++) {
        x[j] = b[i];
    }
}

uint32 get_val(bit *a) {
    uint32 ret = 0;
    for(int i = 1; i <= 32; i++) {
        ret = (ret << 1) | a[i];
    }
    return ret;
}

void print_bits(bit *a, int n, int per) {
    for (int i = 1; i <= n; i++) {
        cout << a[i];
        if (i % per == 0) {
            cout << " ";
        }
    }
    cout << "\n";
}

/**
 * 检测对于轮函数输入差分 40080000 扩展置换后能否得到 2,5,6,7,8 五个S盒输入差分全为0
 * 检测对于轮函数输入差分 02000008 扩展置换后能否得到 1,2,4,5,6 五个S盒输入差分全为0
 * 检测对于轮函数输入差分 405C0000 扩展置换后能否得到 2,5,6,7,8 五个S盒输入差分全为0
 * 求出对于轮函数输入差分 04000000 扩展置换后的输出
 */
void test_expansion() {
//    uint32 delta = 0x40080000U;
//    uint32 delta = 0x00200008U;
//    uint32 delta = 0x405C0000U;
    uint32 delta = 0x04000000U;
    bit r[32 + 1], e[48 + 1];
    get_bits(delta, r);
    expansion(r, e);
    print_bits(e, 48, 6);
}

/**
 * 8个S盒的差分分布表
 */
vector<int> s_xor[8][64][16];

/**
 * 初始化所有S盒的差分分布表
 */
void init_s_xor() {
    for (int index = 0; index < 8; index++) {
        for (int delta = 0; delta < 64; delta++) {
            for (int i = 0, j, k; i < 64; i++) {
                j = delta ^ i;
                k = get_sbox(i, index) ^ get_sbox(j, index);
                s_xor[index][delta][k].push_back(i);
            }
        }
    }
}

/**
 * 打印S盒的差分分布表
 * @param id [0, 8)
 */
void print_s_xor(int id) {
    init_s_xor();
    bitset<6> in;
    bitset<4> out;
    for (int i = 0; i < 64; i++) {
        for (int j = 0; j < 16; j++) {
            in = bitset<6>(i);
            cout << in << " ";
            out = bitset<4>(j);
            cout << out << " ";
            printf("(%d): ", (int) s_xor[id][i][j].size());
            for (auto &k : s_xor[id][i][j]) {
                in = bitset<6>(k);
                cout << in << " ";
            }
            puts("");
        }
    }
}

struct Frac {
  int x, y; // x / y

  Frac() {
      x = y = 1;
  }

  Frac(int x, int y) {
      this->x = x;
      this->y = y;
      this->reduce();
  }

  int gcd(int a, int b) {
      return b == 0 ? a : gcd(b, a % b);
  }

  void reduce() {
      int g = gcd(x, y);
      x /= g;
      y /= g;
  }

  void multiply(Frac &p) {
      p.reduce();
      this->x *= p.x;
      this->y *= p.y;
      this->reduce();
  }

  void print() {
      cout << x << "/" << y << "\n";
  }
};

/**
 * 当轮函数的输入差分为 04000000，输出差分为 40080000 时，检测其差分概率是否为 1/4
 * 当轮函数的输入差分为 00540000，输出差分为 04000000 时，检测其差分概率是否为 (16 * 10) / (64 * 64) = 5 / 128
 */
void test_possibility() {
    uint32 D1 = 0x04000000U, D2 = 0x40080000U;
//    uint32 D1 = 0x00540000U, D2 = 0x04000000U;
    bit d1[32 + 1], d2[32 + 1], out[32 + 1], in[48 + 1];
    get_bits(D1, d1);
    get_bits(D2, d2);
    expansion(d1, in);
    print_bits(in, 48, 6);
    reverse_permutation(d2, out);
    print_bits(out, 32, 4);
    init_s_xor();
//    print_s_xor(1);
    Frac ans;
    for (int i = 1, j = 1; i <= 48 && j <= 32; i += 6, j += 4) {
        int x = 0, y = 0, index = i / 6;
        for (int k = i; k < i + 6; k++) x = (x << 1) | in[k];
        for (int k = j; k < j + 4; k++) y = (y << 1) | out[k];
        if (x == 0) continue;
        if (s_xor[index][x][y].size() > 0) {
            Frac cur(s_xor[index][x][y].size(), 64);
            ans.multiply(cur);
        }
    }
    ans.print();
}

/**
 * 检测每个 S 盒的输出差分对应输入差分的平均分布情况，大概均处于 0.75~0.8 之间
S[0]: 0.7949
S[1]: 0.7861
S[2]: 0.7969
S[3]: 0.6855
S[4]: 0.7656
S[5]: 0.8047
S[6]: 0.7725
S[7]: 0.7715
 */
void test_noise() {
    init_s_xor();
    for (int i = 0; i < 8; i++) {
        double p = 0;
        for (int x = 0; x < 64; x++) {
            int sum = 0;
            for (int y = 0; y < 16; y++) {
                if (s_xor[i][x][y].size() != 0) {
                    sum++;
                }
            }
            p += 1.0 * sum / 16;
        }
        printf("S[%d]: %.4lf\n", i, p / 64);
    }
}

void test_reduced_crypt() {
    uint64 PLAIN = 0x86FA1C2B1F51D3BEULL;
    uint64 KEY = 0x34E9E71A20756231ULL;
    bit k[64 + 1], p[64 + 1], c[64 + 1];
    DES_KEY desKey;
    bitset<64> bk(KEY);
    for (int i = 1, j = 63; i <= 64; i++, j--) {
        k[i] = bk[j];
    }
    set_key(k, &desKey);
    bitset<64> bp(PLAIN);
    for (int i = 1, j = 63; i <= 64; i++, j--) {
        p[i] = bp[j];
    }
    des_reduced_crypt(p, c, &desKey, 6, ENCRYPT);
    int t = 0;
    for (int i = 1; i <= 64; i++) {
        t = (t << 1) | c[i];
        if (i % 8 == 0) {
            printf("%02X", t);
            t = 0;
        }
    }
    puts("");
}

/**
 * Biham-Shamir 论文 P32
 * 检测对于 04000000，经过轮函数后得到的 P(0W00 0000) = X00Y Z0T0 中 W,X,Y,Z 的分布情况
 * 预期结果 W = {0, 1, 2, 3, 8, 9, A, B}, X = {0, 4}, Y = {0, 8}, Z = {0, 4}, T = 0
 * 实际结果 W = {3, 5, 7, 9, A, B, C, E, F}, X = {0, 4}, Y = {0, 8}, Z = {0, 4}, T = {0, 1}
 */
void test_possibility2() {
    int s2_xor = 8;
    bit in[32 + 1], out[32 + 1];
    set<int> s;
    vector<int> vec;
    for(int i = 0; i < 64; i++) {
        for(int j = 0; j < 64; j++) {
            if((i ^ j) == s2_xor) {
                int k = get_sbox(i, 1) ^ get_sbox(j, 1);
                vec.push_back(k);
                s.insert(k);
            }
        }
    }
    // 输出 P(0W00 0000) 中 W 的取值情况
    cout << "W = {";
    for(auto val: s) {
        cout << val << " ";
    }
    cout << "}" << endl;
    map<uint32, int> mp;
    for(auto &val: vec) {
        memset(in, 0, sizeof(in));
        bitset<4> b(val);
        for(int i = 0; i < 4; i++) {
            in[5 + i] = b[3 - i];
        }
        permutation(in, out);
        print_bits(out, 32, 4);
        mp[get_val(out)]++;
    }
    uint32 n1 = 0x40080000U;
    uint32 n2 = 0x00004000U;
    int cnt = 0;
    // P(0W00 0000) = 40080000 的概率
    cout << mp[n1] << "/64" << endl;
    for(auto it = mp.begin(); it != mp.end(); it++) {
        if((it->first & n2) != 0) {
            cnt += it->second;
        }
    }
    // P(0W00 0000) = *00* 40*0 的概率
    cout << cnt << "/64" << endl;
}

int main() {
//    test_stable();
//    test_crypt();
//    test_reduced_crypt();
//    test_expansion();
    test_possibility();
    test_possibility2();
    return 0;
}

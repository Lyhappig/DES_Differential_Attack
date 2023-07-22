#include "three_attack.hpp"
using namespace std;

/**
 * 明文对的差分
 */
bit delta_plain[NUM][65];

/**
 * 密文对的差分
 */
bit delta_cypher[NUM][65];
bit plain[NUM * 2][65];
bit cypher[NUM * 2][65];
DES_KEY desKey;

/**
 * 候选子密钥的计数器
 */
int J[8][64];

/**
 * 根据给定NUM对的明文字符串，初始化为明文比特
 */
void get_plain() {
    bitset<64> bk;
    for (int i = 0; i < NUM; i++) {
        bk.reset();
        for (int j = 0; j < sp[i][0].size(); j++) {
            bitset<4> b = mp[sp[i][0][j]];
            bk <<= 4;
            for (int k = 0; k < 4; k++) bk[k] = b[k];
        }
        for (int j = 1, k = 63; j <= 64; j++, k--) plain[i][j] = bk[k];
        bk.reset();
        for (int j = 0; j < sp[i][1].size(); j++) {
            bitset<4> b = mp[sp[i][1][j]];
            bk <<= 4;
            for (int k = 0; k < 4; k++) bk[k] = b[k];
        }
        for (int j = 1, k = 63; j <= 64; j++, k--) plain[i + NUM][j] = bk[k];
#ifdef PRINT_PLAIN
        bits_print_bytes(plain[i], 64);
        bits_print_bytes(plain[i + NUM], 64);
#endif
    }
}

void get_cypher() {
    for(int i = 0; i < NUM; i++) {
        des_reduced_crypt(plain[i], cypher[i], &desKey, 3, ENCRYPT);
        des_reduced_crypt(plain[i + NUM], cypher[i + NUM], &desKey, 3, ENCRYPT);
#ifdef PRINT_CYPHER
        bits_print_bytes(cypher[i], 64);
        print_bits(cypher[i], 64, true);
        bits_print_bytes(cypher[i + NUM], 64);
        print_bits(cypher[i + NUM], 64, true);
#endif
    }
}

/**
 * 获取明文对的差分和密文对的差分
 */
void get_dp_dc() {
    for(int i = 0; i < NUM; i++) {
        bits_xor(delta_plain[i], plain[i], plain[i + NUM], 64);
        bits_xor(delta_cypher[i], cypher[i], cypher[i + NUM], 64);
    }
#ifdef PRINT_DELTA
    for(int i = 0; i < NUM; i++) {
        print_bits(delta_plain[i]);
        print_bits(delta_cypher[i]);
    }
#endif
}

void init() {
    init_map();
    init_key(&desKey);
    get_plain();
    get_cypher();
    get_dp_dc();
    init_s_xor();
}

/**
 * 三轮差分分析主体
 * @param dp 一对明文的差分
 * @param dc 一对密文的差分
 * @param c1 密文1
 * @param c2 密文2
 */
void three_attack(bit *dp, bit *dc, bit *cy, bit *cy_) {
    // L0的差分；密文对右半部分L3, L3_；密文对左半部分差分 delta_R3
    bit delta_L0[32 + 1], L3[32 + 1], L3_[32 + 1], delta_R3[32 + 1];
    for(int i = 1; i <= 32; i++) delta_L0[i] = dp[i];
    for(int i = 1; i <= 32; i++) L3[i] = cy[32 + i];
    for(int i = 1; i <= 32; i++) L3_[i] = cy_[32 + i];
    for(int i = 1; i <= 32; i++) delta_R3[i] = dc[i];

    // 计算明文对S盒的输入，B1, B2；差分为B_
    bit B1[48 + 1], B2[48 + 1], B_[48 + 1], C_[32 + 1];
    expansion(L3, B1);
    expansion(L3_, B2);
    bits_xor(B_, B1, B2, 48);

    for(int i = 1; i <= 32; i++) delta_L0[i] ^= delta_R3[i];
    reverse_permutation(delta_L0, C_);

    for(int l1 = 1, l2 = 1; l1 <= 48 && l2 <= 32; l1 += 6, l2 += 4) {
        int in = 0, out = 0, b = 0;
        int index = l1 / 6;
        for(int r1 = l1; r1 < l1 + 6; r1++) {
            in = (in << 1) | B_[r1];
            b = (b << 1) | B1[r1];
        }
        for(int r2 = l2; r2 < l2 + 4; r2++) out = (out << 1) | C_[r2];
        for(auto &x: s_xor[index][in][out]) {
            int possible_key = x ^ b;
            J[index][possible_key]++;
        }
    }
}

void solve() {
    init();
    for(int i = 0; i < NUM; i++) {
        three_attack(delta_plain[i], delta_cypher[i], cypher[i], cypher[i + NUM]);
    }
    bitset<48> attack_key;
    for(int i = 0; i < 8; i++) {
        for(int j = 0; j < 64; j++) {
            if(J[i][j] == NUM) {
                bitset<6> b(j);
                attack_key <<= 6;
                for(int k = 0; k < 6; k++) attack_key[k] = b[k];
                break;
            }
        }
    }
    printf("attack_key is: ");
    int t = 0;
    for(int i = 48; i >= 0; i--) {
        if((i + 1) % 4 == 0 && i < 47) {
            printf("%X", t);
            t = 0;
        }
        t = (t << 1) | attack_key[i];
    }
    printf("%X", t);
    puts("");
#ifdef PRINT_J
    for(int i = 0; i < 8; i++) {
        for(int j = 0; j < 64; j++) {
            cout << J[i][j] << " ";
            if((j + 1) % 16 == 0) cout << "\n";
        }
        cout << "\n\n";
    }
#endif
}

int main() {
    solve();
    return 0;
}

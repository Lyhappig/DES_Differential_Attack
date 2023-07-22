#include "des.hpp"
using namespace std;

void rotate_left(bit *x, int num) {
    bit temp[30];
    if(num == 1) {
        for(int i = 1; i <= 27; i++) temp[i] = x[i + 1];
        temp[28] = x[1];
    } else {
        for(int i = 1; i <= 26; i++) temp[i] = x[i + 2];
        temp[27] = x[1];
        temp[28] = x[2];
    }
    for(int i = 1; i <= 28; i++) x[i] = temp[i];
}

void set_key(bit *K, DES_KEY *desKey) {
    bit temp[60], l[30], r[30];
    for(int i = 0; i < 56; i++) temp[i + 1] = K[PC1_Box[i]];
    for(int i = 0; i < MAX_ROUNDS; i++) {
        for(int j = 1; j <= 56; j++) {
            if(j < 29) l[j] = temp[j];
            else r[j - 28] = temp[j];
        }
        rotate_left(l, Shift_R[i]);
        rotate_left(r, Shift_R[i]);
        for(int j = 1; j <= 56; j++) {
            if(j < 29) temp[j] = l[j];
            else temp[j] = r[j - 28];
        }
        for(int j = 0; j < 48; j++) {
            desKey->rd_key[i][j + 1] = temp[PC2_Box[j]];
        }
    }
}

/**
 * n比特异或：x = y ^ z
 * @param x
 * @param y
 * @param z
 * @param n
 */
void bits_xor(bit *x, bit *y, bit *z, int n) {
    for(int i = 1; i <= n; i++) {
        x[i] = y[i] ^ z[i];
    }
}


/**
 * 轮函数扩展置换
 * @param in
 * @param out
 */
void expansion(const bit *in, bit *out) {
    for(int i = 0; i < 48; i++) {
        out[i + 1] = in[EP_Box[i]];
    }
}


/**
 * 轮函数P置换
 * @param in
 * @param out
 */
void permutation(const bit *in, bit *out) {
    for(int i = 0; i < 32; i++) {
        out[i + 1] = in[P_Box[i]];
    }
}

/**
 * 轮函数P的逆置换
 * @param in
 * @param out
 */
void reverse_permutation(const bit *in, bit *out) {
    for(int i = 0; i < 32; i++) {
        out[i + 1] = in[RP_Box[i]];
    }
}


/**
 * S盒映射函数
 * @param x 6比特输入
 * @param index S盒的编号
 * @return 4比特输出
 */
int get_sbox(int x, int index) {
    bitset<6> b(x);
    int p = b[5] * 2 + b[0];
    int q = b[4] * 8 + b[3] * 4 + b[2] * 2 + b[1];
    return S_Box[index][p * 16 + q];
}


static void round_function(bit *r, DES_KEY *desKey, int index) {
    bit epr[50], ans[50];
    expansion(r, epr);
    bits_xor(epr, desKey->rd_key[index], epr, 48);
    for(int i = 1, j = 1, x, y, id; i <= 48; i += 6, j += 4) {
        x = epr[i] * 2 + epr[i + 5];
        y = epr[i + 1] * 8 + epr[i + 2] * 4 + epr[i + 3] * 2 + epr[i + 4];
        id = x * 16 + y;
        x = S_Box[i / 6][id];
        ans[j] = (x >> 3) & 1;
        ans[j + 1] = (x >> 2) & 1;
        ans[j + 2] = (x >> 1) & 1;
        ans[j + 3] = x & 1;
    }
    permutation(ans, r);
}

void des_crypt(const bit *p, bit *c, DES_KEY *desKey, int enc) {
    bit temp[65], l[35], r[35], tt[35];
    for(int i = 0; i < 64; i++) temp[i + 1] = p[IP_Box[i]];
    for(int i = 1; i <= 64; i++) {
        if(i <= 32) l[i] = temp[i];
        else r[i - 32] = temp[i];
    }
    if(enc) {
        for(int i = 0; i < MAX_ROUNDS; i++) {
            for(int j = 1; j <= 32; j++) tt[j] = r[j];
            round_function(r, desKey, i);
            bits_xor(r, l, r, 32);
            for(int j = 1; j <= 32; j++) l[j] = tt[j];
        }
    } else {
        for(int i = MAX_ROUNDS - 1; i >= 0; i--) {
            for(int j = 1; j <= 32; j++) tt[j] = r[j];
            round_function(r, desKey, i);
            bits_xor(r, l, r, 32);
            for(int j = 1; j <= 32; j++) l[j] = tt[j];
        }
    }
    for(int i = 1; i <= 64; i++) {
        if(i <= 32) temp[i] = r[i];
        else temp[i] = l[i - 32];
    }
    for(int i = 0; i < 64; i++) c[i + 1] = temp[RIP_Box[i]];
}

void des_reduced_crypt(const bit *p, bit *c, DES_KEY *desKey, int rounds, int enc) {
    bit temp[65], l[35], r[35], tt[35];
    for(int i = 1; i <= 64; i++) temp[i] = p[i];
    for(int i = 1; i <= 64; i++) {
        if(i <= 32) l[i] = temp[i];
        else r[i - 32] = temp[i];
    }
    if(enc) {
        for(int i = 0; i < rounds; i++) {
            for(int j = 1; j <= 32; j++) tt[j] = r[j];
            round_function(r, desKey, i);
            bits_xor(r, l, r, 32);
            for(int j = 1; j <= 32; j++) l[j] = tt[j];
        }
    } else {
        for(int i = rounds - 1; i >= 0; i--) {
            for(int j = 1; j <= 32; j++) tt[j] = r[j];
            round_function(r, desKey, i);
            bits_xor(r, l, r, 32);
            for(int j = 1; j <= 32; j++) l[j] = tt[j];
        }
    }
    for(int i = 1; i <= 64; i++) {
        if(i <= 32) temp[i] = r[i];
        else temp[i] = l[i - 32];
    }
    for(int i = 1; i <= 64; i++) c[i] = temp[i];
}
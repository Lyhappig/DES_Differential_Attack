#include "eight_attack.hpp"
using namespace std;

DES_KEY desKey;
bit plain[NUM * 2 + 10][64 + 1];
bit cypher[NUM * 2 + 10][64 + 1];
map<uint64, bool> vis;
set<int> is_inactive;

/**
 * 2^{18} 的部分密钥比特计数器
 */
int key_count[1 << 18];

/**
 * 最终攻击得到的第 8 轮轮密钥部分比特
 */
int attack_key[48];

void init_inactive(uint32 delta_R5) {
    bit in[32 + 1], out[48 + 1];
    uint32_bits(delta_R5, in);
    expansion(in, out);
    is_inactive.clear();
    for(int i = 1; i <= 48; i += 6) {
        int x = 0;
        for(int j = i; j < i + 6; j++) x = (x << 1) | out[j];
        if(!x) {
            is_inactive.insert(i / 6);
        }
    }
#ifdef PRINT_INACTIVE
    cout << "Attacked S-Box is: ";
    for(auto &val: is_inactive) {
        cout << val + 1 << " ";
    }
    cout << "\n";
#endif
}

void get_plain(uint64 delta_plain) {
    uint64 x;
    srand(time(0));
    for(int i = 0; i < NUM; i++) {
        x = 0;
        for(int j = 0; j < 8; j++) {
            x = (x << 8) | (rand() % 256);
        }
        while(vis.count(x) || vis.count(delta_plain ^ x)) {
            x = 0;
            for(int j = 0; j < 8; j++) {
                x = (x << 8) | (rand() % 256);
            }
        }
        vis[x] = vis[delta_plain ^ x] = true;
        uint64_bits(x, plain[i]);
        uint64_bits(delta_plain ^ x, plain[i + NUM]);
    }
}

void get_cypher() {
    for(int i = 0; i < NUM; i++) {
        des_reduced_crypt(plain[i], cypher[i], &desKey, ATK_ROUNDS, ENCRYPT);
        des_reduced_crypt(plain[i + NUM], cypher[i + NUM], &desKey, ATK_ROUNDS, ENCRYPT);
    }
}

void init_attack(uint64 delta_plain, uint32 delta_R5) {
    memset(plain, 0, sizeof(plain));
    memset(cypher, 0, sizeof(cypher));
    vis.clear();
    is_inactive.clear();
    init_inactive(delta_R5);
    get_plain(delta_plain);
    get_cypher();
}


int filter(const bit *delta_B8, const bit *B8, const bit *delta_C8) {
//    int mul = 1;
    for(int l1 = 1, l2 = 1; l1 <= 48 && l2 <= 32; l1 += 6, l2 += 4) {
        int s_idx = l1 / 6;
        if(!is_inactive.count(s_idx)) continue;
        int in = 0, out = 0, b = 0;
        for(int r1 = l1; r1 < l1 + 6; r1++) {
            in = (in << 1) | delta_B8[r1];
            b = (b << 1) | B8[r1];
        }
        for(int r2 = l2; r2 < l2 + 4; r2++) out = (out << 1) | delta_C8[r2];
        if(s_xor[s_idx][in][out].empty()) return true;
//        mul *= s_xor[s_idx][in][out].size();
    }
    return false;
//    return mul <= threshold;
}

vector<int> possible_key[3];
void dfs(int d, int now) {
    if(d >= 3) {
        key_count[now]++;
        return;
    }
    for(auto &x: possible_key[d]) {
        dfs(d + 1, (now << 6) | x);
    }
}

int get_attack_box_idx(vector<int> &attack_box, int x) {
    for(int i = 0; i < attack_box.size(); i++) {
        if(attack_box[i] == x) {
            return i;
        }
    }
    return -1;
}

bool attack_box_count(vector<int> &attack_box, int x) {
    for(auto &val: attack_box) {
        if(val == x) {
            return true;
        }
    }
    return false;
}

void eight_attack(uint32 dl5, int pair_id, int &number, vector<int> &attack_box) {
    bit delta_L5[32 + 1];
    uint32_bits(dl5, delta_L5);
    // 获得第 8 轮 S 盒输入差分
    bit L8[32 + 1], L8_[32 + 1], B8[48 + 1], B8_[48 + 1], delta_B8[48 + 1];
    for(int i = 1; i <= 32; i++) L8[i] = cypher[pair_id][32 + i];
    for(int i = 1; i <= 32; i++) L8_[i] = cypher[pair_id + NUM][32 + i];
    expansion(L8, B8);
    expansion(L8_, B8_);
    bits_xor(delta_B8, B8, B8_, 48);
    // 获得第 8 轮 S 盒输出差分
    bit delta_R8[32 + 1], delta_C8[32 + 1], in[32 + 1];
    for(int i = 1; i <= 32; i++) {
        delta_R8[i] = cypher[pair_id][i] ^ cypher[pair_id + NUM][i];
    }
    bits_xor(in, delta_L5, delta_R8, 32);
    reverse_permutation(in, delta_C8);

    if(filter(delta_B8, B8, delta_C8)) return;
    number++;

    for(int l1 = 1, l2 = 1; l1 <= 48 && l2 <= 32; l1 += 6, l2 += 4) {
        int s_idx = l1 / 6;
        if(!attack_box_count(attack_box, s_idx + 1)) continue;
        int in_num = 0, out_num = 0, b = 0;
        for(int r1 = l1; r1 < l1 + 6; r1++) {
            in_num = (in_num << 1) | delta_B8[r1];
            b = (b << 1) | B8[r1];
        }
        for(int r2 = l2; r2 < l2 + 4; r2++) out_num = (out_num << 1) | delta_C8[r2];
        for(auto &x: s_xor[s_idx][in_num][out_num]) {
            int pk_idx = get_attack_box_idx(attack_box, s_idx + 1);
            possible_key[pk_idx].emplace_back(x ^ b);
        }
    }
    dfs(0, 0);
    for(int i = 0; i < 3; i++) possible_key[i].clear();
}

bool solve(uint64 delta_plain, uint32 delta_L5, uint32 delta_R5, vector<int> &attack_box) {
    init_attack(delta_plain, delta_R5);
    int right_num = 0;
    for(int i = 0; i < NUM; i++) {
        eight_attack(delta_L5, i, right_num, attack_box);
    }
    cout << "right pair number: " << right_num << endl;
    // 寻找最大计数的子密钥部分比特
    int ans = 0, top = 1 << 18, p_key = -1;
    for(int i = 0; i < top; i++) {
        if(key_count[i] > ans) {
            ans = key_count[i];
            p_key = i;
        }
    }
    if(p_key == -1) {
        cout << "attack failed" << endl;
        return false;
    }

    bitset<18> b(p_key);

    for(int i = 2; i >= 0; i--) {
        for(int j = (attack_box[i] - 1) * 6, k = 5; k >= 0; j++, k--) {
            attack_key[j] = b[k];
        }
        b >>= 6;
    }
    return true;
}

int main() {
    init_key(&desKey);
    init_s_xor();
    memset(attack_key, -1, sizeof(attack_key));
    uint64 delta_plain = 0x405C000004000000ULL;
    uint32 delta_L5 = 0x04000000U;
    uint32 delta_R5 = 0x405C0000U;
    // 第一次攻击 S6, S7, S8 对应的 18 比特轮密钥
    vector<int> attack_box1 = {6, 7, 8};
    memset(key_count, 0, sizeof(key_count));
    bool result = solve(delta_plain, delta_L5, delta_R5, attack_box1);
    if(!result) exit(-1);
    // 第二次攻击 S2，S5，S6 对应的 18 比特轮密钥
    vector<int> attack_box2 = {2, 5, 6};
    memset(key_count, 0, sizeof(key_count));
    result = solve(delta_plain, delta_L5, delta_R5, attack_box2);
    if(!result) exit(-1);
    // 攻击完成，破解得到 30 比特的第 8 轮轮密钥
    cout << "\nattack finished: \n";
    cout << "8round key is: ";
    for(int i = 1; i <= 48; i++) {
        cout << desKey.rd_key[ATK_ROUNDS - 1][i];
        if(i % 6 == 0) {
            cout << " ";
        }
    }
    cout << "\nattack key is: ";
    for(int i = 0; i < 48; i++) {
        if(attack_key[i] == -1) {
            cout << "?";
        } else {
            cout << attack_key[i];
        }
        if((i + 1) % 6 == 0) {
            printf(" ");
        }
    }
    puts("");
    return 0;
}

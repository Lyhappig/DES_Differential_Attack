#include "six_attack.hpp"
using namespace std;

DES_KEY desKey;
bit plain[NUM * 2 + 10][64 + 1];
bit cypher[NUM * 2 + 10][64 + 1];
map<uint64, bool> vis;

/**
 * 抽象图模型中的点
 */
Node nodes[NUM];

/**
 * 最终攻击得到的第六轮轮密钥部分比特
 */
int attack_key[48];

void init_inactive(uint32 delta_R3) {
    bit in[32 + 1], out[48 + 1];
    uint32_bits(delta_R3, in);
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

void init_attack(uint64 delta_plain, uint32 delta_R3) {
    memset(plain, 0, sizeof(plain));
    memset(cypher, 0, sizeof(cypher));
    vis.clear();
    is_inactive.clear();
    for(int i = 0; i < NUM; i++) {
        for(int j = 0; j < 8; j++) {
            nodes[i].mask[j].reset();
        }
    }
    init_inactive(delta_R3);
    get_plain(delta_plain);
    get_cypher();
}

/**
 * 求出最大团
 * @param n 图上点的个数
 * @param P 最大团集合
 */
void max_clique(int n, Clique &ans) {
    // "更大团"候选集合
    vector<Clique> P, Q;
    map<set<int>, bool> clq_vis;
    for(int i = 1; i <= n; i++) {
        P.emplace_back(Clique());
        P[i - 1].idx.insert(i);
        P[i - 1].root = nodes[i];
    }
    while(true) {
        for(auto &clq: P) {
            for(int i = 1; i <= n; i++) {
                if(clq.idx.count(i)) continue;
                if(!clq.root.has_edge(nodes[i])) continue;
                Clique new_clq = clq;
                new_clq.add_node(nodes[i], i);
                if(!clq_vis.count(new_clq.idx)) {
                    clq_vis[new_clq.idx] = true;
                    Q.emplace_back(new_clq);
                }
            }
        }
        if(Q.empty()) break;
        P.clear();
        for(auto &clq: Q) {
            P.emplace_back(clq);
        }
        Q.clear();
        clq_vis.clear();
    }
    cout << "max clique's group size is: " << P.size() << "\n";
    cout << "true right pair number is: " << P.back().idx.size() << "\n";
    ans = P.back();
}

/**
 * 是否因错误对过滤
 * @param delta_B6
 * @param B6
 * @param delta_C6
 * @return
 */
bool filter(const bit *delta_B6, const bit *B6, const bit *delta_C6) {
    for(int l1 = 1, l2 = 1; l1 <= 48 && l2 <= 32; l1 += 6, l2 += 4) {
        int s_idx = l1 / 6;
        if(!is_inactive.count(s_idx)) continue;
        int in = 0, out = 0, b = 0;
        for(int r1 = l1; r1 < l1 + 6; r1++) {
            in = (in << 1) | delta_B6[r1];
            b = (b << 1) | B6[r1];
        }
        for(int r2 = l2; r2 < l2 + 4; r2++) out = (out << 1) | delta_C6[r2];
        if(s_xor[s_idx][in][out].empty()) return true;
    }
    return false;
}

/**
 * 六轮攻击主体
 * @param dl3 第三轮左半部分的差分
 * @param pair_id 明文对的ID
 */
void six_attack(uint32 dl3, int pair_id, int &number) {
    bit delta_L3[32 + 1];
    uint32_bits(dl3, delta_L3);
    // 获得第六轮S盒输入差分
    bit L6[32 + 1], L6_[32 + 1], B6[48 + 1], B6_[48 + 1], delta_B6[48 + 1];
    for(int i = 1; i <= 32; i++) L6[i] = cypher[pair_id][32 + i];
    for(int i = 1; i <= 32; i++) L6_[i] = cypher[pair_id + NUM][32 + i];
    expansion(L6, B6);
    expansion(L6_, B6_);
    bits_xor(delta_B6, B6, B6_, 48);
    // 获得第六轮S盒输出差分
    bit delta_C6[32 + 1], in[32 + 1], delta_cypher[64 + 1];
    bits_xor(delta_cypher, cypher[pair_id], cypher[pair_id + NUM], 64);
    bits_xor(in, delta_L3, delta_cypher, 32);
    reverse_permutation(in, delta_C6);

    if(filter(delta_B6, B6, delta_C6)) {
        return;
    }
    number = number + 1;
    // 通过五个S盒的差分分布表得出
    for(int l1 = 1, l2 = 1; l1 <= 48 && l2 <= 32; l1 += 6, l2 += 4) {
        int s_idx = l1 / 6;
        if(!is_inactive.count(s_idx)) continue;
        int in_num = 0, out_num = 0, b = 0;
        for(int r1 = l1; r1 < l1 + 6; r1++) {
            in_num = (in_num << 1) | delta_B6[r1];
            b = (b << 1) | B6[r1];
        }
        for(int r2 = l2; r2 < l2 + 4; r2++) out_num = (out_num << 1) | delta_C6[r2];
        for(auto &x: s_xor[s_idx][in_num][out_num]) {
            int possible_key = x ^ b;
            nodes[number].mask[s_idx][possible_key] = 1;
        }
    }
}

void solve(uint64 delta_plain, uint32 delta_L3, uint32 delta_R3) {
    init_attack(delta_plain, delta_R3);
    int right_num = 0;
    for(int i = 0; i < NUM; i++) {
        six_attack(delta_L3, i, right_num);
    }
    cout << "right plain pair number is: " << right_num << "\n";
    Clique ans;
    max_clique(right_num, ans);
    for(int i = 0; i < 8; i++) {
        if(!is_inactive.count(i)) {
            printf("?????? ");
            continue;
        }
        int six_bits = find_partial_key(ans, i);
        bitset<6> tb(six_bits);
        cout << tb << " ";
        for(int j = 0; j < 6; j++) {
            if(attack_key[i * 6 + j] == -1) {
                attack_key[i * 6 + j] = tb[5 - j];
            }
        }
    }
    puts("");
}


/**
 * 实际攻击时间可能由于随机出正确对的数量而变化
 * @return
 */
int main() {
    init_key(&desKey);
    init_s_xor();
    memset(attack_key, -1, sizeof(attack_key));
    // 第一个差分特征攻击
    cout << "First Attack\n";
    uint64 delta_plain = 0x4008000004000000ULL;
    uint32 delta_L3 = 0x04000000U;
    uint32 delta_R3 = 0x40080000U;
    solve(delta_plain, delta_L3, delta_R3);
    // 第二个差分特征攻击
    cout << "Second Attack\n";
    delta_plain = 0x0020000800000400ULL;
    delta_L3 = 0x00000400U;
    delta_R3 = 0x00200008U;
    solve(delta_plain, delta_L3, delta_R3);
    cout << "\nattack finished: \n";
    // 得到42比特的第六轮轮密钥
    cout << "6round key is: ";
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
}

#include "sns_config_fetch_policy.h"
#include <cassert>
#include <cstdio>
#include <string>
#include <vector>
int main() {
    unsigned available, completed;
    int initial_state;
    assert(scanf("%u %u %d", &available, &completed, &initial_state) == 3);
    nsl::SnsConfigFetchPolicy policy;
    policy.available = available; policy.state = initial_state; policy.completed = completed;
    std::vector<bool> realms;
    auto begin = [&](bool force) { if (policy.begin(force)) realms.push_back(policy.alternate_realm()); };
    char op[16]; unsigned value, accepted;
    while (scanf("%15s %u %u", op, &value, &accepted) == 3) {
        if (std::string(op) == "begin") begin(value != 0);
        else {
            // A divergent policy may stop before the next supplied callback.
            // Return its completed trace normally so counterexamples cannot
            // pass merely by crashing this driver on an inactive callback.
            if (!policy.active) break;
            auto next = policy.complete(accepted && value >= 200 && value < 300);
            if (next == nsl::SnsConfigFetchPolicy::Refresh) begin(true);
            else if (next == nsl::SnsConfigFetchPolicy::Retry) begin(false);
        }
        printf("{\"available\":%d,\"completed\":%u,\"active\":%s,\"realms\":[",
            policy.state, policy.completed, policy.active ? "true" : "false");
        for (unsigned i = 0; i < realms.size(); ++i) printf("%s%s", i ? "," : "", realms[i] ? "true" : "false");
        puts("]}");
    }
}

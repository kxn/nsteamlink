#include "sns_message_queue.h"
#include <cassert>
#include <cstdio>
#include <vector>

int main() {
    constexpr size_t maxMessage = 512 * 1024;
    nsl::SnsMessageQueue q;
    std::vector<uint8_t> bytes(maxMessage, 0xa7);
    assert(q.push(bytes.data(), 3000, maxMessage));
    assert(q.push(nullptr, 0, maxMessage));
    assert(q.push(bytes.data(), bytes.size(), maxMessage));
    assert(!q.push(nullptr, 1, maxMessage));
    assert(!q.push(bytes.data(), maxMessage + 1, maxMessage));
    assert(q.front().size() == 3000 && q.front()[2999] == 0xa7);
    q.pop();
    assert(q.front().empty()); q.pop();
    assert(q.front() == bytes); q.pop(); assert(q.empty());
    for (size_t n = 0; n < q.ByteLimit / maxMessage; ++n)
        assert(q.push(bytes.data(), maxMessage, maxMessage));
    auto held = q.take();
    assert(!q.push(bytes.data(), 1, maxMessage)); // SDK send retains reservation
    q.retry(std::move(held));
    assert(!q.push(bytes.data(), 1, maxMessage));
    held = q.take(); q.finish(held.size());
    assert(q.push(bytes.data(), maxMessage, maxMessage));
    q.clear();
    for (size_t n = 0; n < q.CountLimit; ++n) assert(q.push(nullptr, 0, maxMessage));
    held = q.take();
    assert(!q.push(nullptr, 0, maxMessage)); // zero length still costs one slot
    q.retry(std::move(held));
    held = q.take(); q.finish(held.size());
    assert(q.push(nullptr, 0, maxMessage));
    q.clear();
    uint8_t a = 1, b = 2;
    assert(q.push(&a, 1, maxMessage));
    held = q.take();
    assert(q.push(&b, 1, maxMessage));
    q.retry(std::move(held));
    assert(q.front()[0] == 1); q.pop();
    assert(q.front()[0] == 2); q.pop();
    assert(q.empty());
    puts("PASS SNS whole messages, zero lengths, FIFO retry and reserved byte/count bounds");
}

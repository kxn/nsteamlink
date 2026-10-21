#pragma once
#include <cstddef>
#include <cstdint>
#include <deque>
#include <new>
#include <vector>

namespace nsl {
using SnsMessage = std::vector<uint8_t>;
/* RX FIFO; caller holds its queue mutex. Bounds are port resources, not
 * official protocol message-size constants. TX acceptance belongs to SDK. */
class SnsMessageQueue {
    std::deque<SnsMessage> items;
    size_t bytes = 0;
public:
    static constexpr size_t ByteLimit = 8 * 1024 * 1024;
    static constexpr size_t CountLimit = 4096;
    bool empty() const { return items.empty(); }
    const SnsMessage &front() const { return items.front(); }
    bool push(const uint8_t *p, size_t n, size_t messageLimit) {
        if ((n && !p) || n > messageLimit || n > ByteLimit - bytes ||
            items.size() >= CountLimit)
            return false;
        try {
            if (n) items.emplace_back(p, p + n);
            else items.emplace_back();
            bytes += n;
            return true;
        } catch (const std::bad_alloc &) { return false; }
    }
    void pop() {
        size_t n = items.front().size();
        items.pop_front();
        bytes -= n;
    }
    void clear() { items.clear(); bytes = 0; }
};
}

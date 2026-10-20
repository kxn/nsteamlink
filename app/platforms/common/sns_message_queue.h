#pragma once
#include <cstddef>
#include <cstdint>
#include <deque>
#include <new>
#include <utility>
#include <vector>

namespace nsl {
using SnsMessage = std::vector<uint8_t>;
/* Caller holds its queue mutex. The SDK owner can take one TX message without
 * releasing its byte/count reservation while SendMessage invokes callbacks.
 * Retry then preserves FIFO and cannot exceed the resource budget. These are
 * port resource bounds, not official protocol message-size constants. */
class SnsMessageQueue {
    std::deque<SnsMessage> items;
    size_t bytes = 0, held = 0;
public:
    static constexpr size_t ByteLimit = 8 * 1024 * 1024;
    static constexpr size_t CountLimit = 4096;
    bool empty() const { return items.empty(); }
    const SnsMessage &front() const { return items.front(); }
    bool push(const uint8_t *p, size_t n, size_t messageLimit) {
        if ((n && !p) || n > messageLimit || n > ByteLimit - bytes ||
            items.size() + held >= CountLimit)
            return false;
        try {
            if (n) items.emplace_back(p, p + n);
            else items.emplace_back();
            bytes += n;
            return true;
        } catch (const std::bad_alloc &) { return false; }
    }
    SnsMessage take() {
        SnsMessage message = std::move(items.front());
        items.pop_front();
        ++held;
        return message;
    }
    void finish(size_t n) { bytes -= n; --held; }
    void retry(SnsMessage message) {
        items.emplace_front(std::move(message));
        --held;
    }
    void pop() {
        size_t n = items.front().size();
        items.pop_front();
        bytes -= n;
    }
    void clear() { items.clear(); bytes = held = 0; }
};
}

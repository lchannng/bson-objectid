/*
 * File  : objectid.hpp
 * Author: lchannng <l.channng@gmail.com>
 * Date  : 2021/07/10 12:00:02
 */

#pragma once
#ifndef IJK_OBJECTID_H
#define IJK_OBJECTID_H

/*
cpp implimentation for mongo objectid
https://github.com/mongodb/specifications/blob/master/source/objectid.rst
*/

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <random>
#include <stdexcept>
#include <string>

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#pragma comment(lib, "Ws2_32.lib")
#else
#include <unistd.h>
#endif

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 256
#endif

namespace ijk {

namespace details {
inline uint16_t getpid() {
    uint16_t pid;
#if defined(_WIN32) || defined(_WIN64)
    DWORD real_pid;
    real_pid = GetCurrentProcessId();
    pid = (real_pid & 0xFFFF) ^ ((real_pid >> 16) & 0xFFFF);
#else
    pid = ::getpid();
#endif
    return pid;
}

inline int64_t now_us() {
    auto d = std::chrono::system_clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::microseconds>(d).count();
}

inline uint32_t now() {
    auto d = std::chrono::system_clock::now().time_since_epoch();
    auto t = std::chrono::duration_cast<std::chrono::seconds>(d).count();
    return static_cast<uint32_t>(t);
}

inline std::string gethostname() {
    char hostname[HOST_NAME_MAX];
    if (::gethostname(hostname, HOST_NAME_MAX) != 0) {
        if (errno == ENAMETOOLONG) {
            fprintf(stderr,
                    "hostname exceeds %d characters, truncating.",
                    HOST_NAME_MAX);
        } else {
            fprintf(stderr, "unable to get hostname: %d", errno);
        }
    }
    hostname[HOST_NAME_MAX - 1] = '\0';
    return std::string(hostname);
}

static inline uint8_t parse_hex_char(char hex) {
    switch (hex) {
        case '0':
            return 0;
        case '1':
            return 1;
        case '2':
            return 2;
        case '3':
            return 3;
        case '4':
            return 4;
        case '5':
            return 5;
        case '6':
            return 6;
        case '7':
            return 7;
        case '8':
            return 8;
        case '9':
            return 9;
        case 'a':
        case 'A':
            return 0xa;
        case 'b':
        case 'B':
            return 0xb;
        case 'c':
        case 'C':
            return 0xc;
        case 'd':
        case 'D':
            return 0xd;
        case 'e':
        case 'E':
            return 0xe;
        case 'f':
        case 'F':
            return 0xf;
        default:
            return 0;
    }
}

}  // namespace details

class objectid {
    static constexpr std::size_t k_objectid_binary_length = 12;
    static constexpr std::size_t k_objectid_string_length = k_objectid_binary_length * 2;
public:
    static objectid generate() {
        /*
        4 byte timestamp    5 byte process unique   3 byte counter
        |<----------------->|<---------------------->|<------------>|
        [----|----|----|----|----|----|----|----|----|----|----|----]
        0                   4                   8                   12
        */
        auto &ctx = get_process_unique_context();
        uint32_t now = details::now();
        uint32_t seq = ctx.seq_++;

        auto oid = objectid();
        auto bytes = oid.bytes_.data();
        bytes[0] = static_cast<uint8_t>(now >> 0x18);
        bytes[1] = static_cast<uint8_t>(now >> 0x10);
        bytes[2] = static_cast<uint8_t>(now >> 8);
        bytes[3] = static_cast<uint8_t>(now);
        std::memcpy(bytes + 4, ctx.rand_bytes_.data(), ctx.rand_bytes_.size());
        bytes[9] = static_cast<uint8_t>(seq >> 0x10);
        bytes[10] = static_cast<uint8_t>(seq >> 8);
        bytes[11] = static_cast<uint8_t>(seq);

        return oid;
    }

    static objectid from_string(std::string_view soid) {
        if (soid.size() != k_objectid_string_length) {
            throw std::runtime_error("invalid length");
        }

        auto oid = objectid();
        auto bytes = oid.bytes_.data();

        for (std::size_t i = 0; i < k_objectid_binary_length; ++i) {
            bytes[i] = ((details::parse_hex_char(soid[2 * i]) << 4) |
                        (details::parse_hex_char(soid[2 * i + 1])));
        }

        return oid;
    }

    static objectid from_bytes(const uint8_t *data, std::size_t sz) {
        if (sz != k_objectid_binary_length) {
            throw std::runtime_error("invalid length");
        }

        auto oid = objectid();
        std::memcpy(oid.bytes_.data(), data, sz);
        return oid;
    }

    inline std::string to_string() {
        static constexpr std::string_view hex = "0123456789abcdef";
        std::string res(k_objectid_string_length, 0);
        std::size_t i = 0;
        for (uint8_t c : bytes_) {
            res[i * 2] = hex[c >> 4];
            res[i * 2 + 1] = hex[c & 0xf];
            ++i;
        }
        return res;
    }

    inline const auto &bytes() const{
        return bytes_;
    }

    inline int64_t gen_time() {
        int64_t t = bytes_[0] << 0x18 | bytes_[1] << 0x10 | bytes_[2] << 0x8 |bytes_[3];
        return t;
    }

    inline bool operator==(const objectid &other) const {
        return bytes_ == other.bytes_;
    }

    inline bool operator!=(const objectid &other) const {
        return bytes_ != other.bytes_;
    }

    objectid(objectid &&) = default;

private:
    objectid() = default;

    struct context {
        std::array<uint8_t, 5> rand_bytes_;
        std::atomic_uint32_t seq_;
        uint16_t pid_;

        context() {
            // https://github.com/mongodb/mongo-c-driver/blob/master/src/libbson/src/bson/bson-context.c
            // _bson_context_init_random

            pid_ = details::getpid();
            auto now = details::now_us();
            auto hostname = details::gethostname();

            uint32_t seed = 0;
            seed ^= static_cast<uint32_t>(now / 1000000);  // second
            seed ^= static_cast<uint32_t>(now % 1000000);  // microsecond
            seed ^= static_cast<uint32_t>(pid_);

            auto hostname_chars_left = static_cast<uint32_t>(hostname.length());
            auto ptr = hostname.data();
            while (hostname_chars_left) {
                uint32_t hostname_chunk = 0;
                uint32_t to_copy = hostname_chars_left > 4 ? 4 : hostname_chars_left;

                std::memcpy(&hostname_chunk, ptr, to_copy);
                seed ^= hostname_chunk;
                hostname_chars_left -= to_copy;
                ptr += to_copy;
            }
            std::default_random_engine rg(seed);
            std::uniform_int_distribution<uint32_t> dist;

            seq_ = dist(rg) & 0x007FFFF0;

            uint64_t rand_val = dist(rg);
            rand_val <<= 32;
            rand_val |= dist(rg);
            std::memcpy(rand_bytes_.data(), &rand_val, rand_bytes_.size());
        }
    };

    static inline context &get_process_unique_context() {
        static context ctx;
        return ctx;
    }

private:
    std::array<uint8_t, k_objectid_binary_length> bytes_;
};

}  // namespace ijk

#endif

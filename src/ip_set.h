#ifndef IP_SET
#define IP_SET

#include <cstdint>
#include <span>
#include <string>
#include <string_view>

class ip_set {
public:
    /**
     * @par Example
     * @code
     * ip_set set;
     * set.insert("192.168.0.0/16");
     * @endcode
     */
    bool insert(std::string_view cidr);

    /**
     * @par Example
     * @code
     * ip_set set;
     * set.insert(0x12340000, 16);
     * @endcode
     */
    bool insert(std::span<const std::uint8_t> ip, std::uint8_t bits);

    /**
     * @par Example
     * @code
     * ip_set set;
     * set.insert("192.168.0.0/16");
     * set.contains("192.168.0.1"); // return true
     * @endcode
     */
    bool contains(std::string_view ip_str) const;

    bool contains(std::span<const std::uint8_t> ip) const;

    /**
     * @brief clear the ip_set
     * @par Example
     * @code
     * ip_set set;
     * set.insert("192.168.0.0/16");
     * set.contains("192.168.0.1"); // return true
     * set.clear();
     * set.contains("192.168.0.1"); // return false
     * @endcode
     */
    void clear();

private:
    struct trie_node {
        trie_node* left = nullptr;  // bit 0
        trie_node* right = nullptr; // bit 1
        bool is_complete = false;
    };

    class trie {
    public:
        trie() = default;
        ~trie();

        trie(const trie&) = delete;
        trie& operator=(const trie&) = delete;

        trie(trie&& other) noexcept;
        trie& operator=(trie&& other) noexcept;

        bool insert(std::span<const std::uint8_t> ip, std::uint8_t bits);
        bool contains(std::span<const std::uint8_t> ip) const;
        void clear();

    private:
        trie_node root;
    };

    trie ipv4;
    trie ipv6;
};

#endif

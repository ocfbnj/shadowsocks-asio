#ifndef IP_SET
#define IP_SET

#include <cstdint>
#include <string>

class ip_set {
public:
    ip_set() = default;
    ip_set(const ip_set&) = delete;
    ip_set& operator=(const ip_set&) = delete;
    ip_set(ip_set&& other);
    ip_set& operator=(ip_set&& other);
    ~ip_set();

    /**
     * @par Example
     * @code
     * ip_set set;
     * set.insert("192.168.0.0/16");
     * @endcode
     */
    void insert(const std::string& cidr);

    /**
     * @par Example
     * @code
     * ip_set set;
     * set.insert(0x12340000, 16);
     * @endcode
     */
    void insert(std::uint32_t ip, std::uint8_t bits);

    /**
     * @par Example
     * @code
     * ip_set set;
     * set.insert("192.168.0.0/16");
     * set.contains("192.168.0.1"); // return true
     * @endcode
     */
    bool contains(const std::string& ip) const;

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

    trie_node root;
};

#endif
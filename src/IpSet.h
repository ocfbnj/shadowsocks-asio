#ifndef IP_SET
#define IP_SET

#include <cstdint>
#include <string>

class IpSet {
public:
    IpSet() = default;
    IpSet(const IpSet&) = delete;
    IpSet& operator=(const IpSet&) = delete;
    IpSet(IpSet&& other);
    IpSet& operator=(IpSet&& other);
    ~IpSet();

    /**
     * @par Example
     * @code
     * IPset set;
     * set.insert("192.168.0.0/16");
     * @endcode
     */
    void insert(const std::string& cidr);

    /**
     * @par Example
     * @code
     * IPset set;
     * set.insert(0x12340000, 16);
     * @endcode
     */
    void insert(std::uint32_t ip, std::uint8_t bits);

    /**
     * @par Example
     * @code
     * IPset set;
     * set.insert("192.168.0.0/16");
     * set.contains("192.168.0.1"); // return true
     * @endcode
     */
    bool contains(const std::string& ip) const;

    /**
     * @brief clear the IpSet
     * @par Example
     * @code
     * IPset set;
     * set.insert("192.168.0.0/16");
     * set.contains("192.168.0.1"); // return true
     * set.clear();
     * set.contains("192.168.0.1"); // return false
     * @endcode
     */
    void clear();

private:
    struct TrieNode {
        TrieNode* left = nullptr;  // bit 0
        TrieNode* right = nullptr; // bit 1
        bool is_complete = false;
    };

    TrieNode root;
};

#endif
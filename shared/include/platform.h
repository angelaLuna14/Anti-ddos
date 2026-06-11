#ifndef PLATFORM_H
#define PLATFORM_H

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <iphlpapi.h>
    #pragma comment(lib, "ws2_32.lib")
    #pragma comment(lib, "iphlpapi.lib")
    typedef SOCKET socket_t;
    #define CLOSE_SOCKET closesocket
    #define INVALID_SOCK INVALID_SOCKET
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <netdb.h>
    #include <sys/ioctl.h>
    #include <net/if.h>
    typedef int socket_t;
    #define CLOSE_SOCKET close
    #define INVALID_SOCK -1
#endif

#include <string>
#include <vector>
#include <cstdint>

namespace antiddos {
namespace platform {

class NetworkUtils {
public:
    static bool init_sockets();
    static void cleanup_sockets();
    
    static std::vector<std::string> get_local_interfaces();
    static std::string get_local_ip();
    
    static bool block_ip(const std::string& ip);
    static bool unblock_ip(const std::string& ip);
    static bool block_port(uint16_t port);
    static bool unblock_port(uint16_t port);
    
    static bool set_raw_socket(socket_t& sock);
    static std::string getLastError();
};

} // namespace platform
} // namespace antiddos

#endif // PLATFORM_H
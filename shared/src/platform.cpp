#include "platform.h"
#include <sstream>
#include <iostream>

#ifdef _WIN32
#pragma comment(lib, "iphlpapi.lib")
#endif

namespace antiddos {
namespace platform {

bool NetworkUtils::init_sockets() {
#ifdef _WIN32
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    return result == 0;
#else
    return true;
#endif
}

void NetworkUtils::cleanup_sockets() {
#ifdef _WIN32
    WSACleanup();
#endif
}

std::vector<std::string> NetworkUtils::get_local_interfaces() {
    std::vector<std::string> interfaces;
    
#ifdef _WIN32
    PIP_ADAPTER_INFO adapter_info = nullptr;
    ULONG buffer_size = 0;
    
    GetAdaptersInfo(nullptr, &buffer_size);
    adapter_info = (PIP_ADAPTER_INFO)malloc(buffer_size);
    
    if (GetAdaptersInfo(adapter_info, &buffer_size) == NO_ERROR) {
        PIP_ADAPTER_INFO adapter = adapter_info;
        while (adapter) {
            interfaces.push_back(adapter->AdapterName);
            adapter = adapter->Next;
        }
    }
    
    free(adapter_info);
#else
    // Linux: read /proc/net/dev or use getifaddrs
    interfaces.push_back("eth0");
    interfaces.push_back("lo");
#endif
    
    return interfaces;
}

std::string NetworkUtils::get_local_ip() {
#ifdef _WIN32
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        struct hostent* host = gethostbyname(hostname);
        if (host && host->h_addr_list[0]) {
            struct in_addr addr;
            memcpy(&addr, host->h_addr_list[0], sizeof(struct in_addr));
            return inet_ntoa(addr);
        }
    }
    return "127.0.0.1";
#else
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return "127.0.0.1";
    
    struct sockaddr_in remote;
    remote.sin_family = AF_INET;
    remote.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &remote.sin_addr);
    
    if (connect(sock, (struct sockaddr*)&remote, sizeof(remote)) == 0) {
        getsockname(sock, (struct sockaddr*)&addr, &len);
        close(sock);
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
        return ip;
    }
    close(sock);
    return "127.0.0.1";
#endif
}

bool NetworkUtils::block_ip(const std::string& ip) {
#ifdef _WIN32
    std::string cmd = "netsh advfirewall firewall add rule name=\"Antiblock_";
    cmd += ip + "\" dir=in action=block remoteip=" + ip;
    return system(cmd.c_str()) == 0;
#else
    std::string cmd = "iptables -A INPUT -s " + ip + " -j DROP";
    int result = system(cmd.c_str());
    cmd = "iptables -A OUTPUT -d " + ip + " -j DROP";
    result |= system(cmd.c_str());
    return result == 0;
#endif
}

bool NetworkUtils::unblock_ip(const std::string& ip) {
#ifdef _WIN32
    std::string cmd = "netsh advfirewall firewall delete rule name=\"Antiblock_" + ip + "\"";
    return system(cmd.c_str()) == 0;
#else
    std::string cmd = "iptables -D INPUT -s " + ip + " -j DROP";
    int result = system(cmd.c_str());
    cmd = "iptables -D OUTPUT -d " + ip + " -j DROP";
    result |= system(cmd.c_str());
    return result == 0;
#endif
}

bool NetworkUtils::block_port(uint16_t port) {
#ifdef _WIN32
    std::string cmd = "netsh advfirewall firewall add rule name=\"PortBlock_";
    cmd += std::to_string(port) + "\" dir=in action=block protocol=TCP localport=";
    cmd += std::to_string(port);
    return system(cmd.c_str()) == 0;
#else
    std::string cmd = "iptables -A INPUT -p tcp --dport " + std::to_string(port) + " -j DROP";
    return system(cmd.c_str()) == 0;
#endif
}

bool NetworkUtils::unblock_port(uint16_t port) {
#ifdef _WIN32
    std::string cmd = "netsh advfirewall firewall delete rule name=\"PortBlock_";
    cmd += std::to_string(port) + "\"";
    return system(cmd.c_str()) == 0;
#else
    std::string cmd = "iptables -D INPUT -p tcp --dport " + std::to_string(port) + " -j DROP";
    return system(cmd.c_str()) == 0;
#endif
}

bool NetworkUtils::set_raw_socket(socket_t& sock) {
#ifdef _WIN32
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (sock == INVALID_SOCKET) return false;
    
    BOOL opt = TRUE;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char*)&opt, sizeof(opt)) == SOCKET_ERROR) {
        CLOSE_SOCKET(sock);
        return false;
    }
#else
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) return false;
    
    int opt = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt)) < 0) {
        close(sock);
        return false;
    }
#endif
    return true;
}

std::string NetworkUtils::getLastError() {
#ifdef _WIN32
    int error = WSAGetLastError();
    char msg[256];
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, nullptr, error, 0, msg, sizeof(msg), nullptr);
    return std::string(msg);
#else
    return std::string(strerror(errno));
#endif
}

} // namespace platform
} // namespace antiddos
#include "api_gateway.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <cstring>

#ifdef _WIN32
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#undef DELETE
#define CLOSE_SOCKET closesocket
typedef int ssize_t;
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#define CLOSE_SOCKET close
#endif

namespace antiddos {
namespace api {

APIGateway::APIGateway() = default;

APIGateway::~APIGateway() {
    stop();
}

bool APIGateway::start(uint16_t port, const std::string& bind_address) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (running_) return false;
    
#ifdef _WIN32
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) return false;
#endif
    
    server_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd_ < 0) return false;
    
    int opt = 1;
    setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, bind_address.c_str(), &addr.sin_addr);
    
    if (bind(server_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        CLOSE_SOCKET(server_fd_);
        return false;
    }
    
    if (listen(server_fd_, 128) < 0) {
        CLOSE_SOCKET(server_fd_);
        return false;
    }
    
    running_ = true;
    
    server_thread_ = std::thread([this]() {
        while (running_) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            int client_fd = accept(server_fd_, (struct sockaddr*)&client_addr, &client_len);
            
            if (client_fd < 0) continue;
            
            std::thread(&APIGateway::handle_client, this, client_fd).detach();
        }
    });
    
    return true;
}

void APIGateway::stop() {
    running_ = false;
    
    if (server_fd_ >= 0) {
        CLOSE_SOCKET(server_fd_);
        server_fd_ = -1;
    }
    
    if (server_thread_.joinable()) {
        server_thread_.join();
    }
    
#ifdef _WIN32
    WSACleanup();
#endif
}

bool APIGateway::is_running() const {
    return running_;
}

void APIGateway::add_route(HTTPMethod method, const std::string& path, RouteHandler handler) {
    std::lock_guard<std::mutex> lock(mutex_);
    Route route;
    route.method = method;
    route.path = path;
    route.handler = handler;
    routes_.push_back(route);
}

void APIGateway::remove_route(HTTPMethod method, const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    routes_.erase(
        std::remove_if(routes_.begin(), routes_.end(),
            [method, &path](const Route& r) { return r.method == method && r.path == path; }),
        routes_.end()
    );
}

void APIGateway::add_middleware(Middleware middleware) {
    std::lock_guard<std::mutex> lock(mutex_);
    middleware_.push_back(middleware);
}

void APIGateway::set_auth_enabled(bool enable) {
    std::lock_guard<std::mutex> lock(mutex_);
    auth_enabled_ = enable;
}

void APIGateway::set_api_key(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    api_key_ = key;
}

void APIGateway::set_jwt_secret(const std::string& secret) {
    std::lock_guard<std::mutex> lock(mutex_);
    jwt_secret_ = secret;
}

std::string APIGateway::generate_token(const std::string& user_id, uint32_t expiry_seconds) {
    return "token_" + user_id + "_" + std::to_string(expiry_seconds);
}

bool APIGateway::validate_token(const std::string& token) {
    return !token.empty();
}

APIGateway::Stats APIGateway::get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

void APIGateway::reset_stats() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_ = Stats{};
}

void APIGateway::set_rate_limit(uint32_t requests_per_minute) {
    std::lock_guard<std::mutex> lock(mutex_);
    rate_limit_rpm_ = requests_per_minute;
}

void APIGateway::set_cors_enabled(bool enable) {
    std::lock_guard<std::mutex> lock(mutex_);
    cors_enabled_ = enable;
}

void APIGateway::set_cors_origins(const std::vector<std::string>& origins) {
    std::lock_guard<std::mutex> lock(mutex_);
    cors_origins_ = origins;
}

std::string APIGateway::get_version() const {
    return "1.0.0";
}

std::vector<std::string> APIGateway::get_endpoints() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> result;
    
    for (const auto& route : routes_) {
        std::string method;
        switch (route.method) {
            case HTTPMethod::GET: method = "GET"; break;
            case HTTPMethod::POST: method = "POST"; break;
            case HTTPMethod::PUT: method = "PUT"; break;
            case HTTPMethod::DELETE: method = "DELETE"; break;
            default: method = "UNKNOWN"; break;
        }
        result.push_back(method + " " + route.path);
    }
    
    return result;
}

void APIGateway::handle_client(int client_fd) {
    char buffer[4096];
    memset(buffer, 0, sizeof(buffer));
    
    ssize_t bytes_read = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    if (bytes_read <= 0) {
        CLOSE_SOCKET(client_fd);
        return;
    }
    
    std::string raw_request(buffer, bytes_read);
    APIRequest request = parse_request(raw_request);
    
    stats_.total_requests++;
    
    if (!check_rate_limit(request.client_ip)) {
        APIResponse response;
        response.status_code = 429;
        response.body = "{\"error\":\"Rate limit exceeded\"}";
        std::string serialized = serialize_response(response);
        send(client_fd, serialized.c_str(), serialized.length(), 0);
        CLOSE_SOCKET(client_fd);
        return;
    }
    
    for (auto& mw : middleware_) {
        if (!mw(request)) {
            APIResponse response;
            response.status_code = 403;
            response.body = "{\"error\":\"Forbidden\"}";
            std::string serialized = serialize_response(response);
            send(client_fd, serialized.c_str(), serialized.length(), 0);
            CLOSE_SOCKET(client_fd);
            return;
        }
    }
    
    bool route_found = false;
    for (const auto& route : routes_) {
        if (route.method == request.method && route.path == request.path) {
            if (route.requires_auth && auth_enabled_ && !check_auth(request)) {
                stats_.auth_failures++;
                APIResponse response;
                response.status_code = 401;
                response.body = "{\"error\":\"Unauthorized\"}";
                std::string serialized = serialize_response(response);
                send(client_fd, serialized.c_str(), serialized.length(), 0);
                CLOSE_SOCKET(client_fd);
                return;
            }
            
            APIResponse response = route.handler(request);
            std::string serialized = serialize_response(response);
            send(client_fd, serialized.c_str(), serialized.length(), 0);
            
            stats_.successful_requests++;
            stats_.responses_by_status[response.status_code]++;
            route_found = true;
            break;
        }
    }
    
    if (!route_found) {
        APIResponse response;
        response.status_code = 404;
        response.body = "{\"error\":\"Not found\"}";
        std::string serialized = serialize_response(response);
        send(client_fd, serialized.c_str(), serialized.length(), 0);
        stats_.failed_requests++;
    }
    
    CLOSE_SOCKET(client_fd);
}

APIRequest APIGateway::parse_request(const std::string& raw_request) {
    APIRequest request;
    std::istringstream iss(raw_request);
    std::string line;
    
    if (std::getline(iss, line)) {
        if (line.find("GET") == 0) request.method = HTTPMethod::GET;
        else if (line.find("POST") == 0) request.method = HTTPMethod::POST;
        else if (line.find("PUT") == 0) request.method = HTTPMethod::PUT;
        else if (line.find("DELETE") == 0) request.method = HTTPMethod::DELETE;
        
        size_t path_start = line.find(' ') + 1;
        size_t path_end = line.find(' ', path_start);
        if (path_end != std::string::npos) {
            request.path = line.substr(path_start, path_end - path_start);
        }
    }
    
    while (std::getline(iss, line) && line != "\r") {
        size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string key = line.substr(0, colon);
            std::string value = line.substr(colon + 2);
            value.erase(value.find_last_not_of("\r\n") + 1);
            request.headers[key] = value;
        }
    }
    
    if (request.headers.count("Authorization")) {
        request.auth_token = request.headers["Authorization"];
    }
    
    return request;
}

std::string APIGateway::serialize_response(const APIResponse& response) {
    std::ostringstream oss;
    oss << "HTTP/1.1 " << response.status_code << " OK\r\n";
    oss << "Content-Type: application/json\r\n";
    oss << "Content-Length: " << response.body.length() << "\r\n";
    
    if (cors_enabled_) {
        oss << "Access-Control-Allow-Origin: *\r\n";
    }
    
    oss << "\r\n";
    oss << response.body;
    
    return oss.str();
}

bool APIGateway::check_auth(const APIRequest& request) {
    if (request.auth_token.empty()) return false;
    return validate_token(request.auth_token);
}

bool APIGateway::check_rate_limit(const std::string& client_ip) {
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now().time_since_epoch()
    ).count();
    
    auto& counter = rate_limit_counters_[client_ip];
    
    if (now - counter.second > 60) {
        counter.first = 1;
        counter.second = now;
        return true;
    }
    
    counter.first++;
    return counter.first <= rate_limit_rpm_;
}

} // namespace api
} // namespace antiddos

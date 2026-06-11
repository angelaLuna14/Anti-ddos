#ifndef API_GATEWAY_H
#define API_GATEWAY_H

#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>
#include <functional>
#include <mutex>
#include <thread>
#include <atomic>

namespace antiddos {
namespace api {

enum class HTTPMethod {
    GET,
    POST,
    PUT,
    DELETE,
    PATCH,
    OPTIONS
};

struct APIRequest {
    HTTPMethod method;
    std::string path;
    std::unordered_map<std::string, std::string> headers;
    std::string body;
    std::string client_ip;
    std::string auth_token;
};

struct APIResponse {
    uint16_t status_code;
    std::unordered_map<std::string, std::string> headers;
    std::string body;
};

using RouteHandler = std::function<APIResponse(const APIRequest&)>;
using Middleware = std::function<bool(APIRequest&)>;

struct Route {
    HTTPMethod method;
    std::string path;
    RouteHandler handler;
    std::vector<Middleware> middleware;
    bool requires_auth = true;
    std::string required_role;
};

class APIGateway {
public:
    APIGateway();
    ~APIGateway();
    
    bool start(uint16_t port, const std::string& bind_address = "0.0.0.0");
    void stop();
    bool is_running() const;
    
    void add_route(HTTPMethod method, const std::string& path, RouteHandler handler);
    void remove_route(HTTPMethod method, const std::string& path);
    
    void add_middleware(Middleware middleware);
    
    void set_auth_enabled(bool enable);
    void set_api_key(const std::string& key);
    void set_jwt_secret(const std::string& secret);
    
    std::string generate_token(const std::string& user_id, uint32_t expiry_seconds);
    bool validate_token(const std::string& token);
    
    struct Stats {
        uint64_t total_requests;
        uint64_t successful_requests;
        uint64_t failed_requests;
        uint64_t auth_failures;
        uint32_t active_connections;
        std::unordered_map<std::string, uint32_t> requests_by_endpoint;
        std::unordered_map<uint16_t, uint32_t> responses_by_status;
    };
    
    Stats get_stats() const;
    void reset_stats();
    
    void set_rate_limit(uint32_t requests_per_minute);
    void set_cors_enabled(bool enable);
    void set_cors_origins(const std::vector<std::string>& origins);
    
    std::string get_version() const;
    std::vector<std::string> get_endpoints() const;
    
private:
    void handle_client(int client_fd);
    APIRequest parse_request(const std::string& raw_request);
    std::string serialize_response(const APIResponse& response);
    
    bool check_auth(const APIRequest& request);
    bool check_rate_limit(const std::string& client_ip);
    
    mutable std::mutex mutex_;
    std::vector<Route> routes_;
    std::vector<Middleware> middleware_;
    
    bool running_ = false;
    bool auth_enabled_ = true;
    bool cors_enabled_ = false;
    std::string api_key_;
    std::string jwt_secret_;
    std::vector<std::string> cors_origins_;
    
    uint32_t rate_limit_rpm_ = 1000;
    std::unordered_map<std::string, std::pair<uint32_t, uint64_t>> rate_limit_counters_;
    
    Stats stats_;
    std::thread server_thread_;
    int server_fd_ = -1;
};

} // namespace api
} // namespace antiddos

#endif // API_GATEWAY_H
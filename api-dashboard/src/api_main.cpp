#include "api_gateway.h"
#include <iostream>
#include <string>
#include <csignal>
#include <atomic>

static std::atomic<bool> running(true);

void signal_handler(int signum) {
    std::cout << "\nReceived signal " << signum << ", shutting down..." << std::endl;
    running = false;
}

void print_usage(const char* prog) {
    std::cout << "Usage: " << prog << " [options]" << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -p, --port <port>        API port (default: 8080)" << std::endl;
    std::cout << "  -b, --bind <address>     Bind address (default: 0.0.0.0)" << std::endl;
    std::cout << "  -k, --api-key <key>      API key for authentication" << std::endl;
    std::cout << "  --no-auth                Disable authentication" << std::endl;
    std::cout << "  --cors                   Enable CORS" << std::endl;
    std::cout << "  -h, --help               Show this help" << std::endl;
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    uint16_t port = 8080;
    std::string bind_address = "0.0.0.0";
    std::string api_key;
    bool auth_enabled = true;
    bool cors_enabled = false;
    
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "-p" || arg == "--port") {
            if (i + 1 < argc) port = std::stoi(argv[++i]);
        } else if (arg == "-b" || arg == "--bind") {
            if (i + 1 < argc) bind_address = argv[++i];
        } else if (arg == "-k" || arg == "--api-key") {
            if (i + 1 < argc) api_key = argv[++i];
        } else if (arg == "--no-auth") {
            auth_enabled = false;
        } else if (arg == "--cors") {
            cors_enabled = true;
        } else if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        }
    }
    
    antiddos::api::APIGateway gateway;
    
    gateway.set_auth_enabled(auth_enabled);
    gateway.set_cors_enabled(cors_enabled);
    
    if (!api_key.empty()) {
        gateway.set_api_key(api_key);
    }
    
    gateway.add_route(antiddos::api::HTTPMethod::GET, "/api/v1/status",
        [](const antiddos::api::APIRequest& req) -> antiddos::api::APIResponse {
            antiddos::api::APIResponse resp;
            resp.status_code = 200;
            resp.body = "{\"status\":\"running\",\"version\":\"2.0.0\"}";
            return resp;
        });
    
    gateway.add_route(antiddos::api::HTTPMethod::GET, "/api/v1/stats",
        [](const antiddos::api::APIRequest& req) -> antiddos::api::APIResponse {
            antiddos::api::APIResponse resp;
            resp.status_code = 200;
            resp.body = "{\"requests\":0,\"threats\":0}";
            return resp;
        });
    
    gateway.add_route(antiddos::api::HTTPMethod::GET, "/api/v1/blocked",
        [](const antiddos::api::APIRequest& req) -> antiddos::api::APIResponse {
            antiddos::api::APIResponse resp;
            resp.status_code = 200;
            resp.body = "{\"blocked_ips\":[]}";
            return resp;
        });
    
    gateway.add_route(antiddos::api::HTTPMethod::POST, "/api/v1/block",
        [](const antiddos::api::APIRequest& req) -> antiddos::api::APIResponse {
            antiddos::api::APIResponse resp;
            resp.status_code = 200;
            resp.body = "{\"success\":true}";
            return resp;
        });
    
    gateway.add_route(antiddos::api::HTTPMethod::POST, "/api/v1/unblock",
        [](const antiddos::api::APIRequest& req) -> antiddos::api::APIResponse {
            antiddos::api::APIResponse resp;
            resp.status_code = 200;
            resp.body = "{\"success\":true}";
            return resp;
        });
    
    gateway.add_route(antiddos::api::HTTPMethod::GET, "/api/v1/incidents",
        [](const antiddos::api::APIRequest& req) -> antiddos::api::APIResponse {
            antiddos::api::APIResponse resp;
            resp.status_code = 200;
            resp.body = "{\"incidents\":[]}";
            return resp;
        });
    
    gateway.add_route(antiddos::api::HTTPMethod::GET, "/api/v1/config",
        [](const antiddos::api::APIRequest& req) -> antiddos::api::APIResponse {
            antiddos::api::APIResponse resp;
            resp.status_code = 200;
            resp.body = "{\"config\":{}}";
            return resp;
        });
    
    std::cout << "=============================================" << std::endl;
    std::cout << "  Anti-DDoS API Gateway v2.0.0" << std::endl;
    std::cout << "=============================================" << std::endl;
    std::cout << "  Starting on " << bind_address << ":" << port << std::endl;
    std::cout << "  Auth: " << (auth_enabled ? "Enabled" : "Disabled") << std::endl;
    std::cout << "  CORS: " << (cors_enabled ? "Enabled" : "Disabled") << std::endl;
    std::cout << "=============================================" << std::endl;
    
    if (!gateway.start(port, bind_address)) {
        std::cerr << "Failed to start API Gateway" << std::endl;
        return 1;
    }
    
    std::cout << "API Gateway started successfully" << std::endl;
    std::cout << "Endpoints:" << std::endl;
    for (const auto& endpoint : gateway.get_endpoints()) {
        std::cout << "  " << endpoint << std::endl;
    }
    std::cout << std::endl;
    std::cout << "Press Ctrl+C to stop" << std::endl;
    
    while (running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    
    gateway.stop();
    std::cout << "API Gateway stopped" << std::endl;
    
    return 0;
}
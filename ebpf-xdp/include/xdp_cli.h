#ifndef XDP_CLI_H
#define XDP_CLI_H

#include "xdp_loader.h"
#include <string>
#include <vector>

namespace antiddos {
namespace xdp {

class XDPCli {
public:
    XDPCli();
    ~XDPCli();
    
    void init();
    void run(const std::vector<std::string>& args);
    
    void cmd_load(const std::vector<std::string>& args);
    void cmd_unload(const std::vector<std::string>& args);
    void cmd_status(const std::vector<std::string>& args);
    void cmd_stats(const std::vector<std::string>& args);
    
    void cmd_blacklist_add(const std::vector<std::string>& args);
    void cmd_blacklist_remove(const std::vector<std::string>& args);
    void cmd_blacklist_list(const std::vector<std::string>& args);
    
    void cmd_port_block(const std::vector<std::string>& args);
    void cmd_port_allow(const std::vector<std::string>& args);
    void cmd_port_list(const std::vector<std::string>& args);
    
    void cmd_rate_limit(const std::vector<std::string>& args);
    void cmd_rate_remove(const std::vector<std::string>& args);
    void cmd_rate_list(const std::vector<std::string>& args);
    
    void cmd_config(const std::vector<std::string>& args);
    void cmd_monitor(const std::vector<std::string>& args);
    void cmd_interfaces(const std::vector<std::string>& args);
    
    void cmd_help(const std::vector<std::string>& args);
    
    static XDPCli& instance();
    
private:
    void print_header();
    void print_separator();
    void print_error(const std::string& msg);
    void print_success(const std::string& msg);
    void print_info(const std::string& msg);
    
    XDPLoader loader_;
    bool initialized_ = false;
};

} // namespace xdp
} // namespace antiddos

#endif // XDP_CLI_H
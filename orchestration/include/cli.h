#ifndef CLI_H
#define CLI_H

#include <string>
#include <vector>
#include <functional>

namespace antiddos {

struct Command {
    std::string name;
    std::string description;
    std::vector<std::string> aliases;
    std::function<void(const std::vector<std::string>&)> handler;
};

class CLI {
public:
    CLI();
    ~CLI();
    
    void init();
    void run(int argc, char* argv[]);
    void run_interactive();
    
    void register_command(const Command& cmd);
    void print_help();
    void print_version();
    
    static CLI& instance();
    
private:
    void register_commands();
    void parse_args(const std::vector<std::string>& args);
    
    void cmd_start(const std::vector<std::string>& args);
    void cmd_stop(const std::vector<std::string>& args);
    void cmd_status(const std::vector<std::string>& args);
    void cmd_stats(const std::vector<std::string>& args);
    
    void cmd_block_ip(const std::vector<std::string>& args);
    void cmd_unblock_ip(const std::vector<std::string>& args);
    void cmd_list_blocked(const std::vector<std::string>& args);
    
    void cmd_config(const std::vector<std::string>& args);
    void cmd_set_threshold(const std::vector<std::string>& args);
    void cmd_set_sensitivity(const std::vector<std::string>& args);
    
    void cmd_geo_block(const std::vector<std::string>& args);
    void cmd_geo_allow(const std::vector<std::string>& args);
    void cmd_geo_list(const std::vector<std::string>& args);
    
    void cmd_whitelist_add(const std::vector<std::string>& args);
    void cmd_whitelist_remove(const std::vector<std::string>& args);
    void cmd_whitelist_list(const std::vector<std::string>& args);
    
    void cmd_blacklist_add(const std::vector<std::string>& args);
    void cmd_blacklist_remove(const std::vector<std::string>& args);
    void cmd_blacklist_list(const std::vector<std::string>& args);
    
    void cmd_scan(const std::vector<std::string>& args);
    void cmd_monitor(const std::vector<std::string>& args);
    void cmd_logs(const std::vector<std::string>& args);
    
    void cmd_update(const std::vector<std::string>& args);
    void cmd_export(const std::vector<std::string>& args);
    void cmd_import(const std::vector<std::string>& args);
    
    void print_header();
    void print_separator();
    void print_error(const std::string& msg);
    void print_success(const std::string& msg);
    void print_info(const std::string& msg);
    
    std::string readline(const std::string& prompt);
    
    std::vector<Command> commands_;
    bool running_ = false;
    bool verbose_ = false;
};

} // namespace antiddos

#endif // CLI_H
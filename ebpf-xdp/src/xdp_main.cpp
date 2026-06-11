#include "xdp_cli.h"
#include <iostream>
#include <vector>
#include <string>

int main(int argc, char* argv[]) {
    antiddos::xdp::XDPCli::instance().init();
    
    std::vector<std::string> args;
    for (int i = 1; i < argc; i++) {
        args.push_back(argv[i]);
    }
    
    if (args.empty()) {
        std::cout << "XDP/eBPF Kernel Filter CLI" << std::endl;
        std::cout << "Type 'help' for available commands." << std::endl;
        std::cout << std::endl;
        
        std::string input;
        while (true) {
            std::cout << "xdp> ";
            if (!std::getline(std::cin, input)) break;
            
            if (input.empty()) continue;
            if (input == "quit" || input == "exit") break;
            
            std::vector<std::string> cmd_args;
            std::istringstream iss(input);
            std::string arg;
            while (iss >> arg) {
                cmd_args.push_back(arg);
            }
            
            antiddos::xdp::XDPCli::instance().run(cmd_args);
        }
    } else {
        antiddos::xdp::XDPCli::instance().run(args);
    }
    
    return 0;
}
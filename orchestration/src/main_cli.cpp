#include "cli.h"
#include "logger.h"
#include "platform.h"
#include <iostream>

int main(int argc, char* argv[]) {
    try {
        antiddos::CLI::instance().run(argc, argv);
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
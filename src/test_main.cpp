#include "LogParser.h"
#include <iostream>
#include <fstream>
#include <sstream>

int main(int argc, char** argv)
{
    std::string path = (argc > 1) ? argv[1] : "sample.log";
    std::ifstream f(path);
    if (!f) { std::cerr << "cannot open " << path << "\n"; return 1; }
    std::stringstream ss; ss << f.rdbuf();
    std::string text = ss.str();

    LogParser p("OPC", "1");
    p.findPrimaryPeriods(text);
    std::cout << "==== Feature 1: primary periods (OPC, 1) ====\n";
    std::cout << p.buildPrimaryResults();

    std::cout << "\n==== Feature 2: separate interfaces ====\n";
    auto docs = LogParser::separateInterfaces(text);
    if (docs.empty())
        std::cout << "(none)\n";
    for (const auto& d : docs) {
        std::cout << "[ " << d.first << " ]\n" << d.second << "\n---\n";
    }

    std::cout << "\n==== Feature 3: join messages onto one line ====\n";
    std::cout << joinMessagesOntoOneLine(text);

    std::cout << "\n==== Feature 4: mask IP addresses ====\n";
    std::cout << replaceIpAddresses(text);
    return 0;
}

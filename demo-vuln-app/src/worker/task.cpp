// NSAT Demo Vulnerable Application — C++ Worker Component (Crow HTTP)
// This file intentionally contains security vulnerabilities for NSAT demo purposes.
// DO NOT use in production.

#include <crow.h>
#include <cstdlib>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>

// NSAT-TARGET: Unsafe buffer operation (strcpy without bounds check)
void process_input(const char* user_data) {
    char buf[64];
    // VULN: No bounds check — classic stack buffer overflow
    strcpy(buf, user_data);
}

// NSAT-TARGET: Command injection via popen with user-supplied string
std::string execute_command(const std::string& cmd) {
    char result[1024];
    // VULN: popen with raw user input — arbitrary command execution
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return "error";
    fgets(result, sizeof(result), pipe);
    pclose(pipe);
    return std::string(result);
}

// NSAT-TARGET: Socket binding to INADDR_ANY (0.0.0.0)
int create_server_socket(int port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    // VULN: INADDR_ANY binds to all interfaces, not just localhost
    addr.sin_addr.s_addr = INADDR_ANY;
    bind(sockfd, (struct sockaddr*)&addr, sizeof(addr));
    return sockfd;
}

int main() {
    crow::SimpleApp app;

    CROW_ROUTE(app, "/worker/exec").methods("POST"_method)(
        [](const crow::request& req) {
            auto body = crow::json::load(req.body);
            std::string cmd = body["task"].s();
            // VULN: Command passed directly to popen without sanitization
            std::string output = execute_command(cmd);
            return crow::response(output);
        }
    );

    // VULN: Listening on all interfaces
    app.port(9000).multithreaded().run();
}

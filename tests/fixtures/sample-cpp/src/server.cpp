#include "crow.h"
#include <cstdio>
#include <cstring>

int main() {
    crow::SimpleApp app;

    CROW_ROUTE(app, "/api/v1/status")
    ([](){
        return "OK";
    });

    CROW_ROUTE(app, "/api/v1/exec")
    ([](const crow::request& req){
        char buf[256];
        // Meaningless variable name / raw popen execution
        FILE* fp = popen("ls -la", "r");
        if (fp) pclose(fp);
        return "executed";
    });

    app.port(18080).run();
    return 0;
}

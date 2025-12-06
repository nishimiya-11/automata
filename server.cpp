#include <iostream>
#include <string>
#include <stack>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

using namespace std;

// --- DFA (Command Injection Filter) ---
bool dfa_scan(string payload) {
    int state = 0;
    for (char c : payload) {
        switch (state) {
            case 0: state = (c == 'w') ? 1 : 0; break;
            case 1: state = (c == 'h') ? 2 : (c == 'w' ? 1 : 0); break;
            case 2: state = (c == 'o') ? 3 : (c == 'w' ? 1 : 0); break;
            case 3: state = (c == 'a') ? 4 : (c == 'w' ? 1 : 0); break;
            case 4: state = (c == 'm') ? 5 : (c == 'w' ? 1 : 0); break;
            case 5: state = (c == 'i') ? 6 : (c == 'w' ? 1 : 0); break;
            case 6: return true;
        }
    }
    return state == 6;
}

// --- PDA (DoS / Structure Validator) ---
int pda_validate(string payload) {
    stack<char> s;
    int MAX_DEPTH = 3;

    for (char c : payload) {
        if (c == '<') {
            if (s.size() >= MAX_DEPTH) return 2; // Too deep
            s.push(c);
        } else if (c == '>') {
            if (s.empty()) return 1; // Underflow
            s.pop();
        }
    }

    if (!s.empty()) return 1; // Unbalanced
    return 0;
}

// --- HTTP RESPONSE ---
string http_response(string body) {
    return "HTTP/1.1 200 OK\r\n"
           "Content-Type: text/plain\r\n"
           "Access-Control-Allow-Origin: *\r\n"
           "\r\n" + body;
}

int main() {
    int port = std::atoi(std::getenv("PORT")); // Railway provides PORT
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind(server_fd, (sockaddr*)&addr, sizeof(addr));
    listen(server_fd, 10);

    cout << "C++ HTTP backend running on port " << port << endl;

    while(true){
        int client_fd = accept(server_fd, nullptr, nullptr);
        char buffer[4096] = {0};
        read(client_fd, buffer, 4096);
        string req = buffer;

        // Extract input from URL: /scan?input=PAYLOAD
        string payload = "";
        size_t pos = req.find("GET /scan?input=");
        if(pos != string::npos){
            int start = pos + 17;
            int end = req.find(" ", start);
            payload = req.substr(start, end - start);
        }

        bool malicious = dfa_scan(payload);
        int pda_result = pda_validate(payload);

        string output = (malicious ? "1" : "0") + string("|") + to_string(pda_result);
        string response = http_response(output);
        send(client_fd, response.c_str(), response.size(), 0);
        close(client_fd);
    }
}

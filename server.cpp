// FILE: server.cpp
// PURPOSE: HTTP Wrapper + Advanced DFA (Multi-Signature) + PDA Logic
// STATUS: UPDATED (Multiple Malicious Signatures Added)

#include <iostream>
#include <string>
#include <stack>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <netinet/in.h>
#include <vector>

using namespace std;

// ===================== LAYER 3: DFA LOGIC (Content Filter) =====================
// DEFINITION: A Finite Automaton that accepts a Regular Language (L)
// L = { "whoami", "uname", "id", "cat", "curl", "wget", "rm", "bash", "sh" }
// THEOREM: The union of Regular Languages is also Regular.
bool dfa_scan(string payload) {
    // 1. The Finite Set of Malicious Signatures (The Regular Language)
    vector<string> signatures = {
        "whoami", 
        "uname", 
        "id", 
        "cat", 
        "curl", 
        "wget", 
        "rm", 
        "bash", 
        "sh",
        "sudo",
        "ls",
        "pwd"// added this one too just in case
    };

    // 2. Scan Process (Automaton State Check)
    // In theory, this acts like a state machine running in parallel for each word.
    // If ANY signature is found as a substring, we transition to the Final/Trap State.
    for (const string &sig : signatures) {
        if (payload.find(sig) != string::npos) {
            return true; // Malicious State Reached
        }
    }

    return false; // Clean
}

// ===================== LAYER 4: PDA LOGIC (Protocol Validator) =====================
// RULE: Stack Check > 3 is considered a DoS Attack
int pda_validate(string payload) {
    stack<char> s;
    int MAX_DEPTH = 3;

    for (char c : payload) {
        if (c == '<') {
            if (s.size() >= MAX_DEPTH) return 2; // Security: DoS Attempt
            s.push(c);
        } else if (c == '>') {
            if (s.empty()) return 1; // Syntax: Error
            s.pop();
        }
    }
    if (!s.empty()) return 1; // Syntax: Error
    return 0; // Valid
}

// ===================== UTILITY: URL DECODER =====================
string url_decode(const string &src) {
    string ret;
    int ii;
    for (size_t i = 0; i < src.length(); i++) {
        if (src[i] == '%') {
            if (i + 2 < src.length()) {
                sscanf(src.substr(i + 1, 2).c_str(), "%x", &ii);
                ret += static_cast<char>(ii);
                i += 2;
            }
        } else if (src[i] == '+') {
            ret += ' ';
        } else {
            ret += src[i];
        }
    }
    return ret;
}

// ===================== UTILITY: HTTP RESPONSE =====================
string http_response(string body) {
    return
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Content-Length: " + to_string(body.size()) + "\r\n\r\n" +
        body;
}

// ===================== MAIN SERVER =====================
int main() {
    // Railway Port Configuration
    const char* env_port = getenv("PORT");
    int port = (env_port) ? atoi(env_port) : 8080;
    
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) return 1;

    // Reuse Address (prevents "Address already in use" errors on restart)
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(server_fd, (sockaddr*)&addr, sizeof(addr)) < 0) return 1;
    listen(server_fd, 5);

    cout << "Security WAF Running on Port " << port << endl;

    while (true) {
        int client_fd = accept(server_fd, nullptr, nullptr);
        if (client_fd < 0) continue;

        char buffer[2048] = {0};
        read(client_fd, buffer, 2048);
        string req = buffer;

        // Parse: GET /scan?input=...
        string payload = "";
        string prefix = "GET /scan?input=";
        size_t p = req.find(prefix);
        
        if (p != string::npos) {
            size_t start = p + prefix.length(); 
            size_t end = req.find(" ", start);
            if (end != string::npos) {
                 payload = req.substr(start, end - start);
                 payload = url_decode(payload);
            }
        }

        // Run Security Logic
        bool malicious = dfa_scan(payload);
        int pda_result = pda_validate(payload);

        // Result Format: "1|0" or "0|2" etc.
        string result = (malicious ? "1" : "0") + string("|") + to_string(pda_result);

        string response = http_response(result);
        send(client_fd, response.c_str(), response.size(), 0);
        close(client_fd);
    }

    return 0;
}

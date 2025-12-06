// FILE: server.cpp
// PURPOSE: HTTP Wrapper + DFA & PDA Logic (with URL decoding for Railway)
// STATUS: FIXED (Payload extraction logic corrected)

#include <iostream>
#include <string>
#include <stack>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <netinet/in.h>

using namespace std;

// ===================== DFA LOGIC (Signature: whoami) =====================
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

// ===================== PDA LOGIC (Depth Check > 3) =====================
int pda_validate(string payload) {
    stack<char> s;
    int MAX_DEPTH = 3;

    for (char c : payload) {
        if (c == '<') {
            if (s.size() >= MAX_DEPTH) return 2; // DoS Check
            s.push(c);
        } else if (c == '>') {
            if (s.empty()) return 1; // Syntax Error
            s.pop();
        }
    }
    if (!s.empty()) return 1; // Syntax Error
    return 0; // Safe
}

// ===================== URL DECODING =====================
string url_decode(const string &src) {
    string ret;
    char ch;
    int ii;
    for (size_t i = 0; i < src.length(); i++) {
        if (src[i] == '%') {
            if (i + 2 < src.length()) {
                sscanf(src.substr(i + 1, 2).c_str(), "%x", &ii);
                ch = static_cast<char>(ii);
                ret += ch;
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

// ===================== HTTP RESPONSE =====================
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
    // Railway gives a PORT env var. Fallback to 8080 if not set.
    const char* env_port = getenv("PORT");
    int port = (env_port) ? atoi(env_port) : 8080;
    
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Socket creation failed");
        return 1;
    }

    // Allow restarting the server immediately without waiting for port to free up
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(server_fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Bind failed");
        return 1;
    }

    listen(server_fd, 5);

    cout << "Server running on port " << port << endl;

    while (true) {
        int client_fd = accept(server_fd, nullptr, nullptr);
        if (client_fd < 0) continue;

        char buffer[2048] = {0};
        read(client_fd, buffer, 2048);
        string req = buffer;

        // ========= Extract input from GET /scan?input=xxxx =========
        string payload = "";
        
        // Use a variable so we can measure its length automatically
        string prefix = "GET /scan?input=";
        size_t p = req.find(prefix);
        
        if (p != string::npos) {
            // FIX IS HERE: Use prefix.length() (which is 16)
            size_t start = p + prefix.length(); 
            size_t end = req.find(" ", start);
            
            if (end != string::npos) {
                 payload = req.substr(start, end - start);
                 payload = url_decode(payload);
            }
        }

        // ========= Run DFA & PDA =========
        bool malicious = dfa_scan(payload);
        int pda_result = pda_validate(payload);

        string result = (malicious ? "1" : "0") + string("|") + to_string(pda_result);

        // ========= Send response =========
        string response = http_response(result);
        send(client_fd, response.c_str(), response.size(), 0);
        close(client_fd);
    }

    return 0;
}

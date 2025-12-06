// FILE: server.cpp
// PURPOSE: HTTP Wrapper + Advanced DFA (Signatures) + PDA (Structure & SQL Logic)
// STATUS: UPGRADED (Supports Quote Balancing ' " and Parentheses ( ) )

#include <iostream>
#include <string>
#include <stack>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <netinet/in.h>
#include <vector>

using namespace std;

// ===================== LAYER 3: DFA LOGIC (Signature Scanning) =====================
// Checks if the payload contains ANY blacklisted keywords
bool dfa_scan(string payload) {
    // 1. The Virus/Hack Definitions
    vector<string> signatures = {
        "whoami", "uname", "id", "cat", "curl", "wget", "rm", "bash", "sh", "sudo", // System
        "drop table", "select *", "insert into", // SQL Distinct phrases
        "/etc/passwd", ".env", "1=1", "--" // Sensitive Files
    };

    // 2. Scan in O(N*M) - Basic Substring Search
    // Note: We use lowercase conversion for case-insensitive matching usually, 
    // but for this assignment, direct matching is fine.
    for (const string &sig : signatures) {
        if (payload.find(sig) != string::npos) {
            return true; // DETECTED
        }
    }
    return false;
}

// ===================== LAYER 4: PDA LOGIC (Smart Structure) =====================
// CHECKS:
// 1. Nesting Depth (DoS Protection)
// 2. Unbalanced Quotes ' ' and " " (SQL Injection Protection)
// 3. Unbalanced Parentheses ( ) (SQL/Script Protection)
// 4. Unbalanced Tunnels < > (XSS/HTML)
//
// RETURN CODES:
// 0 = Valid/Safe
// 1 = Syntax Error (Unclosed quotes, broken brackets) - SUSPICIOUS
// 2 = Stack Overflow (Nesting > 3) - DoS ATTACK
int pda_validate(string payload) {
    stack<char> s;
    int MAX_DEPTH = 3;
    bool escaped = false; // To handle things like admin\'123

    for (char c : payload) {
        // Handle Backslash Escapes (e.g. 'Don\'t')
        if (escaped) {
            escaped = false; // Reset and ignore this character logic
            continue;
        }
        if (c == '\\') {
            escaped = true;
            continue;
        }

        // STATE: Are we currently inside a string literal?
        // (Top of stack is ' or ")
        bool inside_quote = (!s.empty() && (s.top() == '\'' || s.top() == '"'));

        if (inside_quote) {
            // INSIDE STRING: Ignore brackets < ( {
            // Only look for the matching CLOSE quote.
            if (c == s.top()) {
                s.pop(); // String Closed Successfully
            }
            // Else: Do nothing, just consume characters
        } 
        else {
            // OUTSIDE STRING: Look for Openers/Closers
            
            // Check DoS Limit
            if (s.size() >= MAX_DEPTH) return 2;

            if (c == '\'') s.push('\'');       // Start SQL String
            else if (c == '"') s.push('"');    // Start Double String
            else if (c == '(') s.push('(');    // Start Logic Group
            else if (c == '<') s.push('<');    // Start Tunnel/HTML

            // Handle Closers
            else if (c == ')') {
                if (s.empty() || s.top() != '(') return 1; // Unbalanced
                s.pop();
            }
            else if (c == '>') {
                if (s.empty() || s.top() != '<') return 1; // Unbalanced
                s.pop();
            }
        }
    }

    // FINAL CHECK: If stack is not empty, something was left open
    if (!s.empty()) return 1; // e.g., admin' (Unclosed quote)
    
    return 0; // Clean
}

// ===================== UTILITY: URL DECODE =====================
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

// ===================== HTTP SERVER SETUP =====================
string http_response(string body) {
    return "HTTP/1.1 200 OK\r\nContent-Length: " + to_string(body.size()) + "\r\nAccess-Control-Allow-Origin: *\r\n\r\n" + body;
}

int main() {
    const char* env_port = getenv("PORT");
    int port = (env_port) ? atoi(env_port) : 8080;
    
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) return 1;

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(server_fd, (sockaddr*)&addr, sizeof(addr)) < 0) return 1;
    listen(server_fd, 5);

    cout << "SecureNet Engine v3.0 (DFA+PDA) Running on Port " << port << endl;

    while (true) {
        int client_fd = accept(server_fd, nullptr, nullptr);
        if (client_fd < 0) continue;

        char buffer[2048] = {0};
        read(client_fd, buffer, 2048);
        string req = buffer;

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

        bool malicious = dfa_scan(payload);
        int pda_result = pda_validate(payload);

        string result = (malicious ? "1" : "0") + string("|") + to_string(pda_result);

        string response = http_response(result);
        send(client_fd, response.c_str(), response.size(), 0);
        close(client_fd);
    }
    return 0;
}

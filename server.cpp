// FILE: server.cpp
// PURPOSE: TCP Protocol Validator (PDA) + Malicious Signature Scanner (DFA)
// TYPE 2: Context-Free Language (Nested TCP States)
// TYPE 3: Regular Language (Malicious Keyword)

#include <iostream>
#include <string>
#include <stack>
#include <vector>
#include <sstream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <netinet/in.h>

using namespace std;

// ===================== LAYER 3: DFA (MALICIOUS SIGNATURES) =====================
// Still useful to catch "malware" payloads inside a valid TCP packet
bool dfa_scan(string payload) {
    vector<string> signatures = {
        "whoami", "uname", "/etc/passwd", "drop table", "union select", 
        "virus.exe", "malware", "botnet"
    };

    for (const string &sig : signatures) {
        if (payload.find(sig) != string::npos) return true; // DETECTED
    }
    return false;
}

// ===================== LAYER 4: PDA (TCP PROTOCOL SEQUENCING) =====================
// GOAL: Verify Nested Handshake Sequencing
// LOGIC:
// 1. "SYN" (Start Session) -> Push to Stack
// 2. "ACK" / "DATA"        -> Current Session Must Exist
// 3. "FIN" (End Session)   -> Pop from Stack (Must match open session)
//
// VALID:   SYN -> DATA -> SYN -> DATA -> FIN -> FIN
// INVALID: SYN -> FIN -> FIN (Stack Underflow - Closing nothing)
// INVALID: SYN -> DATA (Open Session - Incomplete Handshake)
int pda_tcp_validate(string payload) {
    stack<string> sessionStack;
    stringstream ss(payload);
    string token;

    while (ss >> token) {
        // Convert input tokens to what we are looking for
        // (For simplicity in this demo, input is space-separated words)
        
        if (token == "SYN") {
            // OPENING A NEW CONNECTION/TUNNEL
            sessionStack.push("SESSION");
        } 
        else if (token == "FIN") {
            // CLOSING THE MOST RECENT CONNECTION
            if (sessionStack.empty()) return 1; // Error: RESET/Invalid Sequence (Fin without Syn)
            sessionStack.pop(); 
        } 
        else if (token == "ACK" || token == "DATA" || token == "PSH") {
            // SENDING DATA
            if (sessionStack.empty()) return 1; // Error: Data packet without connection
        }
        // DFA signatures (like 'whoami') might be tokens too, but PDA ignores non-flags
    }

    // FINAL CHECK
    if (!sessionStack.empty()) return 2; // Error: ORPHANED SESSION (Connection left open/DoS Risk)
    
    return 0; // Protocol Valid (All Handshakes Closed)
}

// ===================== UTILS =====================
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
        } else if (src[i] == '+') ret += ' ';
        else ret += src[i];
    }
    return ret;
}

string http_response(string body) {
    return "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: " + to_string(body.size()) + "\r\n\r\n" + body;
}

// ===================== MAIN SERVER =====================
int main() {
    const char* env_port = getenv("PORT");
    int port = (env_port) ? atoi(env_port) : 8080;
    
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    bind(server_fd, (sockaddr*)&addr, sizeof(addr));
    listen(server_fd, 5);

    cout << "TCP Logic Server running on " << port << endl;

    while (true) {
        int client_fd = accept(server_fd, nullptr, nullptr);
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
        int pda_code = pda_tcp_validate(payload);

        // FORMAT: IsMalicious | PDA_Code (0=Safe, 1=SequenceErr, 2=OrphanErr)
        string result = (malicious ? "1" : "0") + string("|") + to_string(pda_code);

        string response = http_response(result);
        send(client_fd, response.c_str(), response.size(), 0);
        close(client_fd);
    }
}

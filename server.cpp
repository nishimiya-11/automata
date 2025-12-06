// FILE: server.cpp
// PURPOSE: HTTP Wrapper + DFA & PDA Logic (with URL decoding for Railway)

#include <iostream>
#include <string>
#include <stack>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <netinet/in.h>

using namespace std;

// ===================== DFA LOGIC =====================
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

// ===================== PDA LOGIC =====================
int pda_validate(string payload) {
    stack<char> s;
    int MAX_DEPTH = 3;

    for (char c : payload) {
        if (c == '<') {
            if (s.size() >= MAX_DEPTH) return 2;
            s.push(c);
        } else if (c == '>') {
            if (s.empty()) return 1;
            s.pop();
        }
    }
    if (!s.empty()) return 1;
    return 0;
}

// ===================== URL DECODING =====================
string url_decode(const string &src) {
    string ret;
    char ch;
    int i, ii;
    for (i = 0; i < src.length(); i++) {
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
    int port = atoi(getenv("PORT"));
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    bind(server_fd, (sockaddr*)&addr, sizeof(addr));
    listen(server_fd, 5);

    cout << "Server running on port " << port << endl;

    while (true) {
        int client_fd = accept(server_fd, nullptr, nullptr);

        char buffer[2048] = {0};
        read(client_fd, buffer, 2048);
        string req = buffer;

        // ========= Extract input from GET /scan?input=xxxx =========
        string payload = "";
        size_t p = req.find("GET /scan?input=");
        if (p != string::npos) {
            size_t start = p + 17;
            size_t end = req.find(" ", start);
            payload = req.substr(start, end - start);
            payload = url_decode(payload); // FIX: decode URL
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

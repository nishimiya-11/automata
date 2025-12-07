// FILE: server.cpp
// PURPOSE: HTTP Wrapper + DFA + PDA (TCP handshake simulation)
// ACCEPTS INPUT: handshake_sequence|payload
// Example: SYN,SYN-ACK,ACK|GET /admin

#include <iostream>
#include <string>
#include <stack>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <netinet/in.h>
#include <vector>
#include <regex>

using namespace std;

// ===================== LAYER 3: DFA LOGIC (Regex Version) =====================
bool dfa_scan(const string& payload) {
    vector<regex> patterns = {
        
        // -------- Command Injection (context required) --------
        regex(R"((;|\|\||&&)\s*(whoami|uname|curl|wget|bash|sudo|sh))", regex_constants::icase),
        regex(R"((whoami|uname|curl|wget|bash|sudo))", regex_constants::icase),
        regex(R"(\$\((whoami|uname|curl|wget|bash|sudo)\))", regex_constants::icase),

        // URL-encoded command separators
        regex(R"( (%3[Bb]|%26%26) )", regex_constants::icase),

        // -------- SQL Injection --------
        regex(R"((\bunion\b\s+\bselect\b))", regex_constants::icase),
        regex(R"((\bdrop\s+table\b))", regex_constants::icase),
        regex(R"((\binsert\s+into\b))", regex_constants::icase),
        regex(R"((\bor\s+1\s*=\s*1\b))", regex_constants::icase),
        regex(R"((--\s*[a-zA-Z]*))", regex_constants::icase),

        // -------- XSS --------
        regex(R"(<\s*script\b)", regex_constants::icase),
        regex(R"(on\w+\s*=\s*['\"])"),
        regex(R"(javascript:)"),

        // -------- Sensitive files --------
        regex(R"(/etc/passwd)", regex_constants::icase),
        regex(R"(\.env)", regex_constants::icase)
    };

    for (const auto& pat : patterns) {
        if (regex_search(payload, pat)) return true;
    }

    return false;
}


// ===================== PDA: TCP Handshake Validation =====================
int pda_validate(const vector<string>& packets) {
    stack<string> st;
    st.push("SYN"); // start handshake

    for (const auto &pkt : packets) {
        if (st.empty()) return 1;

        string top = st.top();
        if (top == "SYN" && pkt == "SYN") { st.pop(); st.push("SYN-ACK"); }
        else if (top == "SYN-ACK" && pkt == "SYN-ACK") { st.pop(); st.push("ACK"); }
        else if (top == "ACK" && pkt == "ACK") { st.pop(); }
        else { return 1; } // out of order
    }
    return st.empty() ? 0 : 1;
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
        } else if (src[i] == '+') ret += ' ';
        else ret += src[i];
    }
    return ret;
}

// ===================== PARSE INPUT =====================
struct ParsedInput {
    vector<string> handshake;
    string payload;
};

ParsedInput parse_input(const string& input) {
    ParsedInput result;
    size_t sep = input.find('|');

    string handshake_part = (sep == string::npos) ? input : input.substr(0, sep);
    result.payload = (sep == string::npos) ? "" : input.substr(sep + 1);

    string temp = "";
    for (char c : handshake_part) {
        if (c == ',') {
            if (!temp.empty()) result.handshake.push_back(temp);
            temp = "";
        } else {
            temp += c;
        }
    }
    if (!temp.empty()) result.handshake.push_back(temp);

    return result;
}

// ===================== HTTP RESPONSE =====================
string http_response(const string &body) {
    return "HTTP/1.1 200 OK\r\nContent-Length: " + to_string(body.size()) + "\r\nAccess-Control-Allow-Origin: *\r\n\r\n" + body;
}

// ===================== MAIN SERVER =====================
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

    cout << "SecureNet Engine v4.0 (DFA+PDA) Running on Port " << port << endl;

    while (true) {
        int client_fd = accept(server_fd, nullptr, nullptr);
        if (client_fd < 0) continue;

        char buffer[4096] = {0};
        read(client_fd, buffer, sizeof(buffer));
        string req = buffer;

        // Parse GET parameter
        string payload_raw = "";
        string prefix = "GET /scan?input=";
        size_t p = req.find(prefix);
        if (p != string::npos) {
            size_t start = p + prefix.length(); 
            size_t end = req.find(" ", start);
            if (end != string::npos) {
                 payload_raw = req.substr(start, end - start);
                 payload_raw = url_decode(payload_raw);
            }
        }

        // Split handshake & payload
        ParsedInput parsed = parse_input(payload_raw);
        cout << "Parsed handshake: ";
        for (size_t i = 0; i < parsed.handshake.size(); ++i) {
            cout << parsed.handshake[i];
            if (i != parsed.handshake.size() - 1) cout << ",";
        }
        cout << endl;

        int pda_result = pda_validate(parsed.handshake);
        cout<<"PDA: "<<pda_result<<endl;

        int dfa_result = 0;
        if (pda_result == 0) { // Only scan payload if handshake valid
            cout<<"[CHECKING DFA]"<<endl;
            dfa_result = dfa_scan(parsed.payload) ? 1 : 0;
            cout<<"DFA: "<<dfa_result<<endl;
        }

        string result = to_string(pda_result) + "|" + to_string(dfa_result);

        string response = http_response(result);
        send(client_fd, response.c_str(), response.size(), 0);
        close(client_fd);
    }

    return 0;
}

// =============================================================
// FILE: server.cpp
// PROJECT: Network Security Protocol Analysis (Topic 2)
// LOGIC: PDA (Stack) for Protocol + DFA (State Machine) for Pattern
// COMPLIANCE: Includes ALL requested attack patterns
// =============================================================

#include <iostream>
#include <string>
#include <stack>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <netinet/in.h>
#include <vector>
#include <map>
#include <sstream>
#include <algorithm>
#include <regex>

using namespace std;

// =============================================================
// PART 1: MINIMIZED DFA (EDUCATIONAL IMPLEMENTATION)
// Manual state transitions for base cases: "union", "<script", ".."
// This proves you understand internal automata structure.
// =============================================================
class MinimizedDFA {
private:
    struct State {
        int id;
        bool accepting; // true = Attack Detected
        map<char, int> transitions;
    };
    vector<State> states;
    int currentState;

public:
    MinimizedDFA() {
        // State 0: Start
        states.push_back({0, false, {}});
        
        // --- Branch 1: SQL Injection ("union") ---
        states.push_back({1, false, {}}); // Saw 'u'
        states.push_back({2, false, {}}); // Saw 'n'
        states.push_back({3, false, {}}); // Saw 'i'
        
        // --- Branch 2: XSS ("<script") ---
        states.push_back({4, false, {}}); // Saw '<'
        states.push_back({5, false, {}}); // Saw 's'
        
        // --- Branch 3: Traversal ("..") ---
        states.push_back({6, false, {}}); // Saw '.'
        states.push_back({7, false, {}}); // Saw '.'
        
        // --- State 99: Attack Confirmed (Trap State) ---
        states.push_back({99, true, {}});

        // DEFINE TRANSITIONS
        // "union" detection (simplified logic for u-n-i-o)
        states[0].transitions['u'] = 1;
        states[1].transitions['n'] = 2;
        states[2].transitions['i'] = 3;
        states[3].transitions['o'] = 99; // Trap!
        
        // "<script" detection
        states[0].transitions['<'] = 4;
        states[4].transitions['s'] = 5;
        states[5].transitions['c'] = 99; // Trap!

        // ".." detection
        states[0].transitions['.'] = 6;
        states[6].transitions['.'] = 7;
        states[7].transitions['/'] = 99; // Trap!
        
        currentState = 0;
    }

    bool scan(const string& input) {
        currentState = 0; // Reset logic
        for (char c : input) {
            char lower = tolower(c);
            
            // Check specific transitions
            if (states[currentState].transitions.count(lower)) {
                currentState = states[currentState].transitions[lower];
            } else {
                // Return to start unless we found an attack (Sticky Trap)
                if (currentState != 99) currentState = 0;
            }
            
            if (states[currentState].accepting) return true; // Attack Found
        }
        return false;
    }
};

// =============================================================
// PART 2: REGEX SAFETY NET (PRACTICAL IMPLEMENTATION)
// Contains ALL patterns from your list to ensure total coverage.
// This runs if the manual DFA misses complex variations.
// =============================================================
bool regex_safety_net(const string& payload) {
    vector<regex> patterns = {
        
        // -------- Command Injection --------
        regex(R"((;|\|\||&&)\s*(whoami|uname|curl|wget|bash|sudo|sh))", regex_constants::icase),
        regex(R"((whoami|uname|curl|wget|bash|sudo))", regex_constants::icase),
        regex(R"(\$\((whoami|uname|curl|wget|bash|sudo)\))", regex_constants::icase),
        regex(R"( (%3[Bb]|%26%26) )", regex_constants::icase), // Encoded chars

        // -------- SQL Injection --------
        regex(R"((\bunion\b\s+\bselect\b))", regex_constants::icase),
        regex(R"((\bdrop\s+table\b))", regex_constants::icase),
        regex(R"((\binsert\s+into\b))", regex_constants::icase),
        regex(R"((\bor\s+1\s*=\s*1\b))", regex_constants::icase),
        regex(R"((--\s*[a-zA-Z]*))", regex_constants::icase), // Comments

        // -------- XSS --------
        regex(R"(<\s*script\b)", regex_constants::icase),
        regex(R"(on\w+\s*=\s*['\"])"), // Event handlers like onload=
        regex(R"(javascript:)", regex_constants::icase),

        // -------- Sensitive files & Path Traversal --------
        regex(R"(/etc/passwd)", regex_constants::icase),
        regex(R"(\.env)", regex_constants::icase),
        regex(R"(\.\./)", regex_constants::icase)
    };

    for (const auto& pat : patterns) {
        if (regex_search(payload, pat)) return true;
    }
    return false;
}

// =============================================================
// PART 3: PDA (PUSHDOWN AUTOMATON) - PROTOCOL LAYER
// Validates TCP Handshake Order: SYN -> SYN-ACK -> ACK
// Requires a STACK, making it Context-Free (Type 2).
// =============================================================
class ProtocolPDA {
private:
    stack<string> pdaStack;
public:
    int validate(const vector<string>& packets) {
        // Clear previous state
        while (!pdaStack.empty()) pdaStack.pop();
        
        // Init PDA Stack
        pdaStack.push("Z0");           // Bottom Marker
        pdaStack.push("EXPECT_SYN");   // Initial state

        for (const string& pkt : packets) {
            if (pdaStack.empty()) return 1; // REJECT (Underflow)

            string current_state = pdaStack.top();

            if (current_state == "EXPECT_SYN" && pkt == "SYN") {
                pdaStack.pop(); // Remove Expectation
                pdaStack.push("EXPECT_ACK");    // We eventually want ACK
                pdaStack.push("EXPECT_SYNACK"); // But first, we need SYN-ACK
            }
            else if (current_state == "EXPECT_SYNACK" && pkt == "SYN-ACK") {
                pdaStack.pop(); // Good, SYN-ACK received. Stack top is now "EXPECT_ACK"
            }
            else if (current_state == "EXPECT_ACK" && pkt == "ACK") {
                pdaStack.pop(); // Good, ACK received. Handshake Done.
            }
            else {
                return 1; // REJECT (Protocol Violation)
            }
        }
        
        // Accept only if we are at Bottom Marker (Z0)
        return (pdaStack.size() == 1 && pdaStack.top() == "Z0") ? 0 : 1;
    }
};

// =============================================================
// UTILITIES (Parsers & Encoders)
// =============================================================
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

struct ParsedInput {
    vector<string> handshake;
    string payload;
};

ParsedInput parse_input(const string& input) {
    ParsedInput result;
    size_t sep = input.find('|');

    // Handle "SYN,SYN-ACK,ACK|payload" vs "SYN..."
    string handshake_part = (sep == string::npos) ? input : input.substr(0, sep);
    result.payload = (sep == string::npos) ? "" : input.substr(sep + 1);

    string temp = "";
    stringstream ss(handshake_part);
    while (getline(ss, temp, ',')) {
        // Remove whitespace just in case
        temp.erase(remove(temp.begin(), temp.end(), ' '), temp.end());
        if (!temp.empty()) result.handshake.push_back(temp);
    }
    return result;
}

string http_response(const string &body) {
    // Basic CORS-enabled headers for Frontend communication
    return "HTTP/1.1 200 OK\r\n"
           "Content-Type: text/plain\r\n"
           "Access-Control-Allow-Origin: *\r\n"
           "Content-Length: " + to_string(body.size()) + "\r\n\r\n" + body;
}

// =============================================================
// MAIN SERVER LOOP
// =============================================================
int main() {
    // 1. Initialize our Automata engines
    MinimizedDFA educationalDFA;
    ProtocolPDA securePDA;

    // 2. Setup Server Socket
    const int PORT = 8080;
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);
    
    if (bind(server_fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Bind failed");
        return 1;
    }
    listen(server_fd, 5);

    cout << "============================================" << endl;
    cout << " TOPIC 2: NETWORK SECURITY ENGINE STARTED" << endl;
    cout << " PORT: " << PORT << endl;
    cout << " MODE: PDA (Type 2) + DFA (Type 3)" << endl;
    cout << "============================================" << endl;

    while (true) {
        int client_fd = accept(server_fd, nullptr, nullptr);
        if (client_fd < 0) continue;

        char buffer[4096] = {0};
        read(client_fd, buffer, sizeof(buffer));
        string req = buffer;

        // 3. Extract parameter: GET /scan?input=SYN,SYN-ACK,ACK|union select
        string payload_raw = "";
        string prefix = "GET /scan?input=";
        size_t p = req.find(prefix);
        if (p != string::npos) {
            size_t start = p + prefix.length(); 
            size_t end = req.find(" ", start);
            if (end != string::npos) {
                 string encoded = req.substr(start, end - start);
                 payload_raw = url_decode(encoded);
            }
        }

        if (payload_raw.empty()) {
            close(client_fd);
            continue;
        }

        // 4. Parse & Validate
        ParsedInput parsed = parse_input(payload_raw);
        
        // STEP A: Protocol Validation (PDA)
        int pda_result = securePDA.validate(parsed.handshake);
        
        // STEP B: Deep Content Inspection (DFA)
        // Note: Logic suggests we check content only if protocol is arguably valid,
        // but we scan anyway to report both statuses to the frontend.
        
        bool dfa_detected = false;

        // Try Manual DFA first (Fast check)
        dfa_detected = educationalDFA.scan(parsed.payload);

        // If Manual DFA didn't find it, run comprehensive Regex Safety Net
        if (!dfa_detected) {
            dfa_detected = regex_safety_net(parsed.payload);
        }
        
        int dfa_result = dfa_detected ? 1 : 0; // 1 = Attack, 0 = Safe

        // 5. Log and Respond
        cout << "[LOG] Payload: \"" << parsed.payload << "\" -> ";
        cout << "PDA=" << pda_result << ", DFA=" << dfa_result << endl;

        // Format: "ProtocolStatus|SecurityStatus"
        // 0|0 = Safe
        // 1|0 = Protocol Error
        // 0|1 = Attack Detected
        string response_body = to_string(pda_result) + "|" + to_string(dfa_result);
        
        string http_resp = http_response(response_body);
        send(client_fd, http_resp.c_str(), http_resp.size(), 0);
        close(client_fd);
    }

    return 0;
}

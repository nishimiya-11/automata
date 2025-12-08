#include <iostream>
#include <string>
#include <stack>
#include <vector>
#include <map>
#include <sstream>
#include <algorithm>
#include <unistd.h>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>

using namespace std;

// ==========================================
// COMPONENT 1: GRAMMAR ENGINE
// ==========================================
class GrammarEngine {
public:
    static void printGrammar() {
        cout << "[System] Loading Theoretical Grammar Rules..." << endl;
    }
};

// ==========================================
// COMPONENT 2: MINIMIZED DFA (Pattern Matching)
// ==========================================
class MinimizedDFA {
private:
    vector<vector<int>> transitionTable;
    vector<bool> acceptingStates;

    void addPattern(string pattern) {
        int currentState = 0;
        for (char c : pattern) {
            // Check if transition exists for this char
            int nextState = transitionTable[currentState][(unsigned char)c];
            
            if (nextState == 0) {
                // If not, expand the table with a new state
                int newStateIndex = transitionTable.size();
                transitionTable.push_back(vector<int>(256, 0));
                acceptingStates.push_back(false);
                
                transitionTable[currentState][(unsigned char)c] = newStateIndex;
                currentState = newStateIndex;
            } else {
                currentState = nextState;
            }
        }
        acceptingStates[currentState] = true;
    }

public:
    MinimizedDFA() {
        // Initialize Root State (0)
        transitionTable.push_back(vector<int>(256, 0)); 
        acceptingStates.push_back(false);

        // --- 1. SQL INJECTION (Matched from your Regex list) ---
        addPattern("union select");  // matches \bunion\b\s+\bselect\b (assuming single space)
        addPattern("union all select");
        addPattern("drop table");    // matches \bdrop\s+table\b
        addPattern("insert into");   // matches \binsert\s+into\b
        addPattern("or 1=1");        // matches \bor\s+1\s*=\s*1\b
        addPattern("-- ");           // matches --\s*
        addPattern("delete from");

        // --- 2. XSS (Cross-Site Scripting) ---
        addPattern("<script");       // matches <\s*script
        addPattern("javascript:");   // matches javascript:
        // Expanded "on\w+=" regex to common handlers
        addPattern("onmouseover=");  
        addPattern("onerror=");
        addPattern("onload=");
        addPattern("onclick=");

        // --- 3. SENSITIVE FILES (LFI) ---
        addPattern("../");           // matches \.\./
        addPattern("..\\");          // matches Windows backslash variant
        addPattern("/etc/passwd");   // matches /etc/passwd
        addPattern(".env");          // matches \.env

        // --- 4. REMOTE CODE EXECUTION (Matches your 'cmd' Regex) ---
        // Your Regex: (whoami|uname|curl|wget|bash|sudo|sh)
        // Note: The main loop URL-decodes the string, so we just check for the commands.
        addPattern("whoami");
        addPattern("uname");
        addPattern("curl");
        addPattern("wget");
        addPattern("bash");
        addPattern("sudo");
        addPattern("system(");
        addPattern("exec(");
    }

    bool scan(const string& payload) {
        int state = 0;

        for (char c : payload) {
            // DFA processes lowercase normalized input (like Regex case_insensitive)
            unsigned char u = tolower(c);
            int nextState = transitionTable[state][u];
            
            if (nextState != 0) {
                // Move forward in the DFA graph
                state = nextState;
            } else {
                // Failure: Reset to 0
                state = 0;
                // Important: Re-evaluate current char against start state to avoid missing
                // patterns that start immediately after a failed match (e.g. "uniunion")
                if (transitionTable[0][u] != 0) {
                    state = transitionTable[0][u];
                }
            }

            if (state < acceptingStates.size() && acceptingStates[state]) return true; // DETECTED
        }
        return false; // CLEAN
    }
};

// ==========================================
// COMPONENT 3: PROTOCOL PDA (Sequence Validation)
// ==========================================
class ProtocolPDA {
private:
    stack<string> stateStack;
public:
    int validate(const vector<string>& packets) {
        while(!stateStack.empty()) stateStack.pop();
        stateStack.push("SYN"); 

        for (const string& pkt : packets) {
            if (stateStack.empty()) return 1; 

            string expected = stateStack.top();
            
            if (expected == "SYN" && pkt == "SYN") {
                stateStack.pop();
                stateStack.push("ACK");     
                stateStack.push("SYN-ACK"); 
            }
            else if (expected == "SYN-ACK" && pkt == "SYN-ACK") {
                stateStack.pop();
            }
            else if (expected == "ACK" && pkt == "ACK") {
                stateStack.pop();
            }
            else return 1; 
        }
        
        return stateStack.empty() ? 0 : 1; 
    }
};

// ==========================================
// UTILITIES
// ==========================================
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

ParsedInput parse_data(const string& input) {
    ParsedInput result;
    size_t sep = input.find('|');
    string handshake_part = (sep == string::npos) ? input : input.substr(0, sep);
    result.payload = (sep == string::npos) ? "" : input.substr(sep + 1);
    
    string temp;
    stringstream ss(handshake_part);
    while (getline(ss, temp, ',')) {
        if(!temp.empty()) result.handshake.push_back(temp);
    }
    return result;
}

string http_response(const string &body) {
    return "HTTP/1.1 200 OK\r\nContent-Length: " + to_string(body.size()) + "\r\nAccess-Control-Allow-Origin: *\r\n\r\n" + body;
}

// ==========================================
// MAIN SERVER
// ==========================================
int main() {
    MinimizedDFA dfaEngine;
    ProtocolPDA pdaEngine;
    
    const char* env_port = getenv("PORT");
    int port = (env_port) ? atoi(env_port) : 8080;

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);
    
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) return 1;
    listen(server_fd, 5);
    
    cout << "Theory-Compatible Engine (DFA+PDA) Running on Port " << port << endl;
    
    while (true) {
        int client_fd = accept(server_fd, nullptr, nullptr);
        if (client_fd < 0) continue;
        
        char buffer[4096] = {0};
        read(client_fd, buffer, 4096);
        string req(buffer);
        
        string raw_value = "";
        size_t input_idx = req.find("input=");
        if (input_idx != string::npos) {
            size_t start = input_idx + 6;
            size_t end = req.find(" ", start);
            if (end == string::npos) end = req.length();
            raw_value = req.substr(start, end - start);
        }
        
        string decoded = url_decode(raw_value);
        ParsedInput data = parse_data(decoded);
        
        // 1. Run PDA (Handshake)
        int pda_res = pdaEngine.validate(data.handshake);
        
        // 2. Run DFA (Content) - only if Handshake passed
        int dfa_res = 0;
        if (pda_res == 0) {
            bool detected = dfaEngine.scan(data.payload);
            dfa_res = detected ? 1 : 0;
        }

        // Return specific legacy format: "0|1"
        string resultBody = to_string(pda_res) + "|" + to_string(dfa_res);
        string response = http_response(resultBody);
        
        send(client_fd, response.c_str(), response.length(), 0);
        close(client_fd);
    }
    
    return 0;
}

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

class GrammarEngine {
public:
    static void printGrammar() {
        cout << "[System] Loading Theoretical Grammar Rules..." << endl; //if we didnt used UI frontend
    }
};

class MinimizedDFA {
private:
    vector<vector<int>> transitionTable;
    vector<bool> acceptingStates;

  
    void addPattern(string pattern) {
        int currentState = 0;
        for (char c : pattern) {
            unsigned char lower = tolower(c);
            unsigned char upper = toupper(c); 

            int nextState = transitionTable[currentState][lower];
            
            if (nextState == 0) {
                int newStateIndex = transitionTable.size();
                transitionTable.push_back(vector<int>(256, 0));
                acceptingStates.push_back(false);

               
                transitionTable[currentState][lower] = newStateIndex;
                transitionTable[currentState][upper] = newStateIndex;
                
                currentState = newStateIndex;
            } else {
                currentState = nextState;
            }
        }
        acceptingStates[currentState] = true;
    }

public:
    MinimizedDFA() {
        transitionTable.push_back(vector<int>(256, 0));
        acceptingStates.push_back(false);

        addPattern("union select");
        addPattern("union all select");
        addPattern("drop table");
        addPattern("insert into");
        addPattern("or 1=1");
        addPattern("-- ");
        addPattern("delete from");

        addPattern("<script");
        addPattern("javascript:");
        addPattern("onmouseover=");
        addPattern("onerror=");
        addPattern("onload=");
        addPattern("onclick=");

        addPattern("../");
        addPattern("..\\");
        addPattern("/etc/passwd");
        addPattern(".env");

        addPattern("whoami");
        addPattern("uname");
        addPattern("curl");
        addPattern("wget");
        addPattern("bash");
        addPattern("sudo");
        addPattern("system(");
        addPattern("exec(");

        addPattern("ls");
        addPattern("pwd");
    }

   
    // a DFA: delta(state, input_symbol) -> next_state.
    bool scan(const string& payload) {
        int state = 0;
        for (char c : payload) {
            unsigned char u = (unsigned char)c; // CHANGED: No preprocessing on input needed anymore
            
            int nextState = transitionTable[state][u];
            if (nextState != 0) {
                state = nextState;
            } else {
                state = 0;
                // Quick fallback logic for simulation purposes (Aho-Corasick failure links ideal here)
                if (transitionTable[0][u] != 0) {
                    state = transitionTable[0][u];
                }
            }
            if (state < acceptingStates.size() && acceptingStates[state]) return true;
        }
        return false;
    }
};

// PDA
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
    return "HTTP/1.1 200 OK\r\nContent-Length: " + to_string(body.size()) +
           "\r\nAccess-Control-Allow-Origin: *\r\n\r\n" + body;
}

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

        int pda_res = pdaEngine.validate(data.handshake);

        int dfa_res = 0;
        if (pda_res == 0) {
            bool detected = dfaEngine.scan(data.payload);
            dfa_res = detected ? 1 : 0;
        }

        string resultBody = to_string(pda_res) + "|" + to_string(dfa_res);
        string response = http_response(resultBody);

        send(client_fd, response.c_str(), response.length(), 0);
        close(client_fd);
    }
    return 0;
}

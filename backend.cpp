// FILE: backend.cpp
// PURPOSE: Logic Engine for Command Injection & DoS Protection

#include <iostream>
#include <string>
#include <stack>

using namespace std;

// --- LAYER 3: DFA (Command Injection Filter) ---
// OLD RULE: Block "admin" (Removed - legitimate admins can now login)
// NEW RULE: Block Linux Payload "whoami"
// Logic: State machine tracks the sequence 'w' -> 'h' -> 'o' -> 'a' -> 'm' -> 'i'
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
            case 6: return true; // Trap state: Threat detected
        }
    }
    return state == 6;
}

// --- LAYER 4: PDA (DoS & Structure Validator) ---
// Role: Check balanced brackets < > 
// ADDED FEATURE: Checks Stack Depth. 
// If nesting is > 3 layers deep, it flags a "Stack Overflow/DoS Attack".
// Returns: 0 = Clean, 1 = Syntax Error, 2 = DoS Attack
int pda_validate(string payload) {
    stack<char> s;
    int MAX_DEPTH = 3;

    for (char c : payload) {
        if (c == '<') {
            if (s.size() >= MAX_DEPTH) return 2; // TOO DEEP -> ATTACK
            s.push(c);
        } else if (c == '>') {
            if (s.empty()) return 1; // Underflow
            s.pop();
        }
    }
    
    if (!s.empty()) return 1; // Unbalanced at end
    return 0; // Success
}

int main(int argc, char* argv[]) {
    string payload = "";
    if (argc >= 2) payload = argv[1];

    bool malicious = dfa_scan(payload);
    int pda_result = pda_validate(payload); // Now returns int 0, 1, or 2

    // Output: 1|0, 1|2, 0|0, etc.
    cout << (malicious ? "1" : "0") << "|" << pda_result << endl;
    return 0;
}

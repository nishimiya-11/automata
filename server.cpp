// FILE: server.cpp
// PURPOSE: HTTP Wrapper + DFA + PDA (TCP handshake simulation)
// ACCEPTS INPUT FORMAT: SYN,SYN-ACK,ACK|payload

#include <iostream>
#include <string>
#include <vector>
#include <stack>
#include <map>
#include <sstream>
#include <unistd.h>
#include <netinet/in.h>
using namespace std;

// ===================== MINIMIZED DFA =====================
class MinimizedDFA {
private:
    struct State {
        int id;
        bool accepting;
        map<char,int> t;
    };
    vector<State> s;
    int cur;

public:
    MinimizedDFA() {
        s.push_back({0,false,{}}); // start
        s.push_back({1,false,{}}); // union
        s.push_back({2,false,{}}); // <script
        s.push_back({3,false,{}}); // ;whoami
        s.push_back({4,false,{}}); // /etc/passwd
        s.push_back({5,true ,{}}); // accept

        // SQL union select
        s[0].t['u']=1; s[0].t['U']=1;
        s[1].t['n']=1; s[1].t['i']=1;
        s[1].t['o']=1; s[1].t[' ']=1;
        s[1].t['s']=1; s[1].t['e']=1;
        s[1].t['l']=1; s[1].t['c']=1;
        s[1].t['t']=5;

        // XSS
        s[0].t['<']=2;
        s[2].t['s']=2; s[2].t['c']=2; s[2].t['r']=2;
        s[2].t['i']=2; s[2].t['p']=2; s[2].t['t']=5;

        // Cmd
        s[0].t[';']=3; s[0].t['|']=3;
        s[3].t['w']=3; s[3].t['h']=3;
        s[3].t['o']=3; s[3].t['a']=3;
        s[3].t['m']=3; s[3].t['i']=5;

        // Path traversal
        s[0].t['/']=4;
        s[4].t['e']=4; s[4].t['t']=4; s[4].t['c']=4;
        s[4].t['/']=4; s[4].t['a']=4; s[4].t['s']=4;
        s[4].t['w']=4; s[4].t['d']=5;

        // Default transitions
        for(auto &st : s){
            for(char c=32;c<=126;c++){
                if(!st.t.count(c))
                    st.t[c] = (st.id==5?5:0);
            }
        }
        cur=0;
    }

    void reset(){ cur=0; }

    bool scan(const string& in){
        reset();
        for(char c: in){
            cur = s[cur].t[c];
            if(s[cur].accepting) return true;
        }
        return false;
    }
};

// ===================== PDA HANDSHAKE =====================
class TCPPDA {
private:
    stack<string> st;

public:
    TCPPDA(){ st.push("Z0"); }

    int validate(const vector<string>& h){
        stack<string> empty;
        swap(st,empty);
        st.push("Z0");
        st.push("SYN-EXPECTED");

        for(auto &p : h){
            string top = st.top(); st.pop();

            if(top=="SYN-EXPECTED" && p=="SYN"){
                st.push("ACK-EXPECTED");
                st.push("SYN-ACK");
            }
            else if(top=="SYN-ACK" && p=="SYN-ACK"){
                // ok
            }
            else if(top=="ACK-EXPECTED" && p=="ACK"){
                st.push("ESTABLISHED");
            }
            else if(top=="ESTABLISHED"){
                // OK for extra data after established
            }
            else{
                return 1; // reject
            }
        }

        // Final acceptance: only Z0 left below ESTABLISHED
        while(!st.empty() && st.top()=="ESTABLISHED")
            st.pop();

        return (st.size()==1 && st.top()=="Z0") ? 0 : 1;
    }
};

// ===================== URL DECODE =====================
string url_decode(const string &s){
    string out; int val;
    for(size_t i=0;i<s.size();i++){
        if(s[i]=='%' && i+2<s.size()){
            sscanf(s.substr(i+1,2).c_str(),"%x",&val);
            out.push_back(char(val));
            i+=2;
        }
        else if(s[i]=='+') out+=' ';
        else out+=s[i];
    }
    return out;
}

// ===================== PARSE INPUT =====================
struct Parsed{
    vector<string> handshake;
    string payload;
};

Parsed parse(const string& in){
    Parsed r;
    size_t pos = in.find('|');
    string h = (pos==string::npos? in : in.substr(0,pos));
    r.payload = (pos==string::npos? "" : in.substr(pos+1));

    string tmp="";
    for(char c:h){
        if(c==','){
            if(!tmp.empty()){ r.handshake.push_back(tmp); tmp=""; }
        } else tmp+=c;
    }
    if(!tmp.empty()) r.handshake.push_back(tmp);
    return r;
}

// ===================== HTTP RESPONSE =====================
string http_response(const string &body){
    return "HTTP/1.1 200 OK\r\nContent-Length: "+to_string(body.size())+"\r\nAccess-Control-Allow-Origin: *\r\n\r\n"+body;
}

// ===================== MAIN =====================
int main(){
    int port=8080;
    int fd = socket(AF_INET,SOCK_STREAM,0);

    int opt=1;
    setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family=AF_INET;
    addr.sin_addr.s_addr=INADDR_ANY;
    addr.sin_port=htons(port);

    bind(fd,(sockaddr*)&addr,sizeof(addr));
    listen(fd,5);

    MinimizedDFA dfa;
    TCPPDA pda;

    while(true){
        int client = accept(fd,nullptr,nullptr);
        if(client<0) continue;

        char buff[4096]={0};
        read(client,buff,sizeof(buff));
        string req=buff;

        string prefix="GET /scan?input=";
        size_t p=req.find(prefix);
        string raw="";
        if(p!=string::npos){
            size_t st=p+prefix.length();
            size_t en=req.find(" ",st);
            raw = req.substr(st,en-st);
            raw = url_decode(raw);
        }

        Parsed pr = parse(raw);

        int pda_res = pda.validate(pr.handshake);
        int dfa_res = (pda_res==0 && dfa.scan(pr.payload)) ? 1 : 0;

        string body = to_string(pda_res)+"|"+to_string(dfa_res);
        string res = http_response(body);
        send(client,res.c_str(),res.size(),0);
        close(client);
    }
    return 0;
}

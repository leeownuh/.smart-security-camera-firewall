#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <ctime>

using namespace std;

// Structure to represent a firewall rule
struct FirewallRule {
    string sourceIP;
    int port;
    bool block; // true = block traffic, false = allow traffic
};

// Function to load firewall rules from a configuration file
vector<FirewallRule> loadRulesFromFile(const string &filename) {
    vector<FirewallRule> rules;
    ifstream file(filename);

    if (!file.is_open()) {
        cerr << "Error: Could not open the file " << filename << endl;
        return rules;
    }

    string line;
    while (getline(file, line)) {
        istringstream ss(line);
        string sourceIP, action;
        int port;
        ss >> sourceIP >> port >> action;

        if (!sourceIP.empty() && port > 0) {
            FirewallRule rule;
            rule.sourceIP = sourceIP;
            rule.port = port;
            rule.block = (action == "block"); // Set block flag based on action
            rules.push_back(rule);
        }
    }

    file.close();
    return rules;
}

// Function to get the current time as a string for logging
string getCurrentTime() {
    time_t now = time(0);
    tm *ltm = localtime(&now);
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", ltm);
    return string(buffer);
}

// Function to log activity to a file
void logActivity(const string &sourceIP, int port, const string &action) {
    ofstream logFile("firewall_log.txt", ios::app);  // Open in append mode
    if (!logFile.is_open()) {
        cerr << "Error: Could not open log file." << endl;
        return;
    }

    logFile << getCurrentTime() << " - IP: " << sourceIP << ", Port: " << port << " - Action: " << action << endl;
    logFile.close();
}

// Function to check traffic against firewall rules and log the result
void checkTraffic(const string &sourceIP, int port, const vector<FirewallRule> &rules) {
    for (const auto &rule : rules) {
        if (rule.sourceIP == sourceIP && rule.port == port) {
            if (rule.block) {
                cout << "Traffic blocked: IP " << sourceIP << " on port " << port << endl;
                logActivity(sourceIP, port, "Blocked");
                return;
            } else {
                cout << "Traffic allowed: IP " << sourceIP << " on port " << port << endl;
                logActivity(sourceIP, port, "Allowed");
                return;
            }
        }
    }
    cout << "No specific rule for IP " << sourceIP << " on port " << port << ". Traffic allowed by default." << endl;
    logActivity(sourceIP, port, "Allowed (No rule)");
}

// Main function
int main() {
    // Load firewall rules from a file
    vector<FirewallRule> rules = loadRulesFromFile("firewall_rules.txt");

    // Simulated incoming traffic (replace with actual traffic data)
    vector<pair<string, int>> incomingTraffic = {
        {"192.168.1.10", 80},
        {"192.168.1.15", 443},
        {"10.0.0.1", 22},
        {"192.168.1.100", 8080} // IP not defined in rules
    };

    // Check incoming traffic against firewall rules
    for (const auto &traffic : incomingTraffic) {
        checkTraffic(traffic.first, traffic.second, rules);
    }

    return 0;
}

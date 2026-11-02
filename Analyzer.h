#ifndef ANALYZER_H
#define ANALYZER_H

#include <vector>
#include <memory>
#include <fstream>
#include <sstream>
#include <iostream>
#include <stdexcept>
#include "LogRecord.h"
#include "RiskRule.h"
#include "Case.h"


class Analyzer
{
    std::vector<std::unique_ptr<LogRecord>> logs;
    std::vector<std::unique_ptr<RiskRule>> rules;
    std::vector<Case> cases;
    int nextCaseId = 1;

public:
    Analyzer()
    {
        rules.push_back(std::make_unique<RepeatedFailedLoginRule>(3));
        rules.push_back(std::make_unique<DeniedFileAccessRule>(3));
    }

    // File handling: logs read karna
    void loadLogs(const std::string &filename)
    {
        std::ifstream in(filename);
        if (!in)
        {
            throw std::runtime_error("Log file nahi mili: " + filename);
        }

        std::string line;
        int lineNo = 0;
        while (std::getline(in, line))
        {
            lineNo++;
            std::stringstream ss(line);
            std::string user, event, status, t1, t2;
            ss >> user >> event >> status >> t1 >> t2;

            // Exception handling: galat line ko skip karo
            if (user.empty() || event.empty() || status.empty() || t1.empty())
            {
                std::cerr << "Warning: line " << lineNo << " galat format, skip.\n";
                continue;
            }
            std::string time = t1 + " " + t2;

            if (event == "Login")
            {
                logs.push_back(std::make_unique<LoginRecord>(user, status, time));
            }
            else if (event == "FileAccess")
            {
                logs.push_back(std::make_unique<FileAccessRecord>(user, status, time));
            }
            else
            {
                logs.push_back(std::make_unique<LogRecord>(user, event, status, time));
            }
        }
        std::cout << "Total records load hue: " << logs.size() << "\n";
    }

    // Rules check karo aur flagged activities dikhao
    void analyze()
    {
        for (const auto &rule : rules)
        {
            std::string user;
            if (rule->evaluate(logs, user))
            {
                std::cout << "[FLAGGED] " << rule->name()
                          << " -> User: " << user
                          << " | Risk: " << rule->riskPoints() << "\n";
            }
        }
    }

    // Case banana
    void createCase(const std::string &user, const std::string &reason, int score)
    {
        if (user.empty())
        {
            throw InvalidCaseException("User name khali nahi ho sakta.");
        }
        cases.emplace_back(nextCaseId++, user, reason, score);
        std::cout << "Case #" << cases.back().id << " ban gaya. Severity: "
                  << cases.back().severity << "\n";
    }

    // Case persistence: cases.txt mein save
    void saveCases(const std::string &filename) const
    {
        std::ofstream out(filename);
        if (!out)
            throw std::runtime_error("cases.txt likh nahi paaye.");
        for (const auto &c : cases)
        {
            out << c.id << "|" << c.user << "|" << c.reason << "|"
                << c.riskScore << "|" << c.severity << "\n";
        }
    }

    // Case persistence: cases.txt se load
    void loadCases(const std::string &filename)
    {
        std::ifstream in(filename);
        if (!in)
            return; // pehli baar chalaane par file nahi hogi, ye normal hai

        std::string line;
        while (std::getline(in, line))
        {
            std::stringstream ss(line);
            std::string idStr, user, reason, scoreStr, sev;
            std::getline(ss, idStr, '|');
            std::getline(ss, user, '|');
            std::getline(ss, reason, '|');
            std::getline(ss, scoreStr, '|');
            try
            {
                int id = std::stoi(idStr);
                int score = std::stoi(scoreStr);
                cases.emplace_back(id, user, reason, score);
                nextCaseId = std::max(nextCaseId, id + 1);
            }
            catch (const std::exception &)
            {
                std::cerr << "Warning: cases.txt ki ek line corrupt hai, skip.\n";
            }
        }
    }

    // Findings report save karna
    void saveReport(const std::string &filename) const
    {
        std::ofstream out(filename);
        if (!out)
            throw std::runtime_error("Report file nahi bani.");
        out << "TraceGuard Findings Report\n";
        out << "==========================\n";
        for (const auto &rule : rules)
        {
            std::string user;
            if (rule->evaluate(logs, user))
            {
                out << "Rule: " << rule->name() << " | User: " << user
                    << " | Risk Points: " << rule->riskPoints() << "\n";
            }
        }
        out << "\nTotal cases: " << cases.size() << "\n";
    }
};

#endif
#ifndef RISKRULE_H
#define RISKRULE_H

#include <vector>
#include <map>
#include <memory>
#include <string>
#include "LogRecord.h"

// Abstract base class
class RiskRule
{
public:
    virtual ~RiskRule() = default;

    // Pure virtual: har rule apna logic dega
    virtual bool evaluate(const std::vector<std::unique_ptr<LogRecord>> &logs,
                          std::string &userOut) const = 0;

    virtual std::string name() const = 0;
    virtual int riskPoints() const = 0;
};

// Rule 1: Repeated failed logins
class RepeatedFailedLoginRule : public RiskRule
{
    int threshold;

public:
    explicit RepeatedFailedLoginRule(int t = 3) : threshold(t) {}

    bool evaluate(const std::vector<std::unique_ptr<LogRecord>> &logs,
                  std::string &userOut) const override
    {
        std::map<std::string, int> failCount;
        for (const auto &r : logs)
        {
            if (r->getEvent() == "Login" && r->getStatus() == "failed")
            {
                failCount[r->getUser()]++;
                if (failCount[r->getUser()] >= threshold)
                {
                    userOut = r->getUser();
                    return true;
                }
            }
        }
        return false;
    }

    std::string name() const override { return "Repeated Failed Login"; }
    int riskPoints() const override { return 40; }
};

// Rule 2: Repeated denied file access
class DeniedFileAccessRule : public RiskRule
{
    int threshold;

public:
    explicit DeniedFileAccessRule(int t = 3) : threshold(t) {}

    bool evaluate(const std::vector<std::unique_ptr<LogRecord>> &logs,
                  std::string &userOut) const override
    {
        std::map<std::string, int> denyCount;
        for (const auto &r : logs)
        {
            if (r->getEvent() == "FileAccess" && r->getStatus() == "denied")
            {
                denyCount[r->getUser()]++;
                if (denyCount[r->getUser()] >= threshold)
                {
                    userOut = r->getUser();
                    return true;
                }
            }
        }
        return false;
    }

    std::string name() const override { return "Repeated Denied File Access"; }
    int riskPoints() const override { return 35; }
};

#endif
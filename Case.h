#ifndef CASE_H
#define CASE_H

#include <string>
#include <stdexcept>

class InvalidCaseException : public std::runtime_error
{
public:
    explicit InvalidCaseException(const std::string &msg)
        : std::runtime_error(msg) {}
};

class Case
{
public:
    int id;
    std::string user;
    std::string reason;
    int riskScore;
    std::string severity;

    Case(int i, const std::string &u, const std::string &r, int score)
        : id(i), user(u), reason(r), riskScore(score)
    {
        severity = (score >= 70) ? "HIGH" : (score >= 40) ? "MEDIUM"
                                                          : "LOW";
    }
};

#endif
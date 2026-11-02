#ifndef LOGRECORD_H
#define LOGRECORD_H

#include <string>
#include <sstream>

// Base class
class LogRecord
{
protected:
    std::string user;
    std::string event;
    std::string status;
    std::string time;

public:
    LogRecord(const std::string &u, const std::string &e,
              const std::string &s, const std::string &t)
        : user(u), event(e), status(s), time(t) {}

    virtual ~LogRecord() = default;

    std::string getUser() const { return user; }
    std::string getEvent() const { return event; }
    std::string getStatus() const { return status; }
    std::string getTime() const { return time; }

    // Polymorphic function: har record type apna description dega
    virtual std::string describe() const
    {
        return user + " " + event + " " + status + " " + time;
    }
};

// Derived class 1
class LoginRecord : public LogRecord
{
public:
    LoginRecord(const std::string &u, const std::string &s, const std::string &t)
        : LogRecord(u, "Login", s, t) {}

    std::string describe() const override
    {
        return "[LOGIN] " + user + " | " + status + " | " + time;
    }
};

// Derived class 2
class FileAccessRecord : public LogRecord
{
public:
    FileAccessRecord(const std::string &u, const std::string &s, const std::string &t)
        : LogRecord(u, "FileAccess", s, t) {}

    std::string describe() const override
    {
        return "[FILE] " + user + " | " + status + " | " + time;
    }
};

#endif
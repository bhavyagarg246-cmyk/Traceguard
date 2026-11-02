#include <iostream>
#include <limits>
#include "Analyzer.h"

void showMenu()
{
    std::cout << "\n===== TraceGuard =====\n"
              << "1. Logs analyze karo\n"
              << "2. Case banao\n"
              << "3. Report save karo\n"
              << "4. Exit\n"
              << "Choice: ";
}

int main()
{
    Analyzer app;
    try
    {
        app.loadLogs("logs.txt");
        app.loadCases("cases.txt");
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    int choice = 0;
    while (true)
    {
        showMenu();
        std::cin >> choice;

        try
        {
            if (choice == 1)
            {
                app.analyze();
            }
            else if (choice == 2)
            {
                std::string user, reason;
                int score;
                std::cout << "User name: ";
                std::cin >> user;
                std::cout << "Reason: ";
                std::cin.ignore();
                std::getline(std::cin, reason);
                std::cout << "Risk score (0-100): ";
                std::cin >> score;
                app.createCase(user, reason, score);
                app.saveCases("cases.txt");
            }
            else if (choice == 3)
            {
                app.saveReport("findings_report.txt");
                std::cout << "Report 'findings_report.txt' mein save ho gayi.\n";
            }
            else if (choice == 4)
            {
                break;
            }
            else
            {
                std::cout << "Galat choice.\n";
            }
        }
        catch (const InvalidCaseException &e)
        {
            std::cerr << "Case error: " << e.what() << "\n";
        }
        catch (const std::exception &e)
        {
            std::cerr << "Error: " << e.what() << "\n";
        }
    }
    std::cout << "TraceGuard band ho raha hai.\n";
    return 0;
}
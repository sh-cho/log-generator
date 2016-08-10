#include "classes.hpp"

/// MAIN
int main(int argc, const char *argv[])
{
    srand((unsigned)time(nullptr));
    std::random_device rd;
    std::mt19937 gen(rd());

    assert(argc == 1);
    
    /// CONFIG, LOG FILES
    ifstream conf;
    ofstream logs;

    /// LOG GENERATOR
    LogGenerator log_generator;
    

    try
    {
        conf.open("log-config.txt");
        if (!conf)
            throw std::runtime_error("Config file open failed.");

        /// LOAD CONFIG
        conf >> log_generator.option;
        conf.close();

        /// PRINT INFO
        cout << log_generator.option << endl;

        /// GENERATE LOGS
        log_generator.generate_logs(gen);

        /// PUT LOG TO FILE
        logs.open(log_generator.option.company_name + string(".log"));
        if (!logs)
            throw std::runtime_error("log file open failed");

        log_generator.put(logs);
        logs.close();

        cout << "--- 로그 출력 완료 ---" << endl;
    }
    catch(const std::exception& e)
    {
        cout << "ERR: " << e.what() << endl;
    }

    return 0;
}
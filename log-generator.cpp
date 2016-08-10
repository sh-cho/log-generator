///
/// LOG GENERATOR PROGRAM.
/// ----------------------
/// config file is needed. (log-config.txt)
/// compile:    g++ -std=c++11 -o log-generator log-generator.cpp
/// run:        ./log-generator (output-log-name)
///         ex) ./log-generator log1.txt
///
/// @date   2016-08-04
/// @author 조성현
///

///
/// CONFIG FILE FORMAT
/// ------------------
/// company_name                #회사 이름
/// YYYY MM DD                  #로그 시작 일자
/// YYYY MM DD                  #로그 종료 일자
/// HH MM SS                    #정상 시작 시간 (24h)
/// HH MM SS                    #정상 종료 시간       --> 정상 시작 시간 < 정상 종료 시간 이어야함
/// num_of_normal_users         #일반 사용자 수(IP 개수)
/// num_of_suspects             #비정상적인 이용을 하는 사용자 수
/// num_of_device_types         #device 종류 개수
/// [device1, 30, 50, 10000000] #device 이름, 개수, 사용량 최소값, 최대값(정상범주, byte)
/// [device2, 10, 10, 100]
/// ...
/// num_of_normal_logs          #정상로그의 수
/// num_of_suspicious_logs      #이상로그의 수
///

///
/// LOG FORMAT
/// ----------
/// filename: YYYYMMDD-YYYYMMDD.log
///           from     to date
/// 
/// file content:
/// [TIMESTAMP] [IP] [device_name] [usage] [(C|R|U|D)]
///
/// ex)
/// [2016-08-04/23:09:13] [58.62.1.77] [printer1] [300] [c]
/// [2016-08-04/23:11:24] [58.62.1.77] [usb1] [1000000] [d]
/// ...
///
/// (C|R|U|D) mean software's default operation; Create, Read, Update, Delete.
///

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <random>
#include <string>
#include <vector>
using namespace std;

/// TYPEDEF
typedef unsigned long long ULL;


/// FORWARD DECLARATION
struct CSHDate;
struct CSHTime;
struct CSHLog;
struct Device;


/// STRUCT DEFINITIONS
struct CSHDate
{
    int year;
    int month;
    int day;

    CSHDate() {}
    // CSHDate(const CSHDate& dt)
    //     : year(dt.year), month(dt.month), day(dt.day)
    // {
    // }
    CSHDate(int _year, int _month, int _day)
        : year(_year), month(_month), day(_day)
    {
    }

    // CSHDate& operator=(const CSHDate& dt)
    // {
    //     year = dt.year;
    //     month = dt.month;
    //     day = dt.day;
    //     return (*this);
    // }
    bool operator<(const CSHDate& dt) const
    {
        return (year*365+month*12+day < dt.year*365+dt.month*12+dt.day);
    }
    bool operator==(const CSHDate& dt) const
    {
        return (year==dt.year && month==dt.month && day==dt.day);
    }
    bool operator!=(const CSHDate& dt) const
    {
        return !(*this == dt);
    }
    bool operator>(const CSHDate& dt) const
    {
        return !(*this<dt || *this==dt);
    }
    bool operator>=(const CSHDate& dt) const
    {
        return (*this>dt || *this==dt);
    }

    friend ostream& operator<<(ostream& os, const CSHDate& dt);
};

struct CSHTime
{
    int hour;
    int min;
    int sec;

    CSHTime() {}
    // CSHTime(const CSHTime& ti)
    //     : hour(ti.hour), min(ti.min), sec(ti.sec)
    // {
    // }
    CSHTime(int _hour, int _min, int _sec)
        : hour(_hour), min(_min), sec(_sec)
    {
    }

    // CSHTime& operator=(const CSHTime& ti)
    // {
    //     hour = ti.hour;
    //     min = ti.min;
    //     sec = ti.sec;
    //     return (*this);
    // }
    bool operator<(const CSHTime& ti) const
    {
        return (hour*3600+min*60+sec < ti.hour*3600+ti.min*60+ti.sec);
    }
    bool operator==(const CSHTime& ti) const
    {
        return (hour==ti.hour && min==ti.min && sec==ti.sec);
    }
    bool operator!=(const CSHTime& ti) const
    {
        return !(*this == ti);
    }
    bool operator>(const CSHTime& ti) const
    {
        return !(*this<ti || *this==ti);
    }
    bool operator>=(const CSHTime& ti) const
    {
        return (*this>ti || *this==ti);
    }

    friend ostream& operator<<(ostream& os, const CSHTime& ti);
};

struct CSHLog
{
    //TIMESTAMP
    CSHDate timestamp_date;
    CSHTime timestamp_time;

    //IP
    string ip;

    //DEVICE NAME
    string device_name;

    //usage
    ULL usage;

    //method
    char method;

    CSHLog() {}
    // CSHLog(const CSHLog& lg)
    //     : timestamp_date(lg.timestamp_date), timestamp_time(lg.timestamp_time)
    //     , ip(lg.ip), device_name(lg.device_name)
    //     , usage(lg.usage), method(lg.method)
    // {
    // }

    // CSHLog& operator=(const CSHLog& lg)
    // {
    //     timestamp_date = lg.timestamp_date;
    //     timestamp_time = lg.timestamp_time;
    //     ip = lg.ip;
    //     device_name = lg.device_name;
    //     usage = lg.usage;
    //     method = lg.method;
    //     return (*this);
    // }
    bool operator<(const CSHLog& lg) const
    {
        if (timestamp_date < lg.timestamp_date)
            return true;
        else if (timestamp_date > lg.timestamp_date)
            return false;
        else    //timestamp_date == lg.timestamp_date
        {
            if (timestamp_time < lg.timestamp_time)
                return true;
            else    //timestamp_time >= lg.timestamp_time
                return false;
        }
    }

    friend ostream& operator<<(ostream& os, const CSHLog& lg);
};

struct Device
{
    string name;
    ULL min_usage;
    ULL max_usage;
    inline void assign(string _name, ULL _minu, ULL _maxu)
    {
        name = _name;
        min_usage = _minu;
        max_usage = _maxu;
    }
};



CSHDate generate_date(const CSHDate& begin_date, const CSHDate& end_date);
CSHTime generate_time(const CSHTime& normal_begin_time, const CSHTime& normal_end_time, bool is_normal, mt19937& gen);
CSHLog generate_log(const CSHDate& begin_date, const CSHDate& end_date, const CSHTime& normal_begin_time, const CSHTime& normal_end_time, const vector<string>& ips, const vector<Device>& devices, const vector<char>& methods, mt19937& gen, bool is_normal);
void generate_ips(vector<string>& normal_ips, vector<string>& suspect_ips, int num_of_normal_users, int num_of_suspects);

/// MAIN
int main(int argc, const char *argv[])
{
    srand((unsigned)time(nullptr));
    std::random_device rd;
    std::mt19937 gen(rd());

    /// assert(argc == 2);
    assert(argc == 1);
    
    /// CONFIG, LOG FILES
    ifstream conf;
    ofstream logs;

    /// CONFIG VARIABLES
    string company_name;
    CSHDate begin_date, end_date;
    CSHTime begin_time, end_time;
    vector<Device> devices;
    int num_of_normal_users,
        num_of_suspects,
        num_of_device_types,
        num_of_normal_logs,
        num_of_suspicious_logs;
    vector<char> methods = {'C', 'R', 'U', 'D'};


    


    try
    {
        conf.open("log-config.txt");
        

        /// LOAD CONFIG START
        conf >> company_name;
        conf >> begin_date.year >> begin_date.month >> begin_date.day
             >> end_date.year >> end_date.month >> end_date.day;
        conf >> begin_time.hour >> begin_time.min >> begin_time.sec
             >> end_time.hour >> end_time.min >> end_time.sec;
        conf >> num_of_normal_users >> num_of_suspects
             >> num_of_device_types;

        string device_name;
        int num_of_devices;
        ULL min_usage, max_usage;
        Device dev;
        for (int i=0; i<num_of_device_types; ++i)
        {
            conf >> device_name >> num_of_devices >> min_usage >> max_usage;
            for (int j=0; j<num_of_devices; ++j)
            {
                dev.assign(device_name + to_string(j+1), min_usage, max_usage);
                devices.push_back(dev);
            }
        }

        conf >> num_of_normal_logs >> num_of_suspicious_logs;
        conf.close();
        /// LOAD CONFIG END


        /// PRINT INFO
        cout << "--- settings ---" << endl;
        cout << "시작~종료 일자:\t\t" << begin_date << " ~ " << end_date << endl;
        cout << "정상 근무 시간:\t\t" << begin_time << " ~ " << end_time << endl;
        cout << "비정상/일반 사용자 수:\t" << num_of_suspects << " / " << num_of_normal_users << endl;
        cout << "비정상/정상로그:\t" << num_of_suspicious_logs << " / " << num_of_normal_logs << endl;
        cout << "장치 종류 갯수:\t\t" << num_of_device_types << endl;


        /// CREATE IPs
        vector<string> normal_ips, suspect_ips;
        generate_ips(normal_ips, suspect_ips, num_of_normal_users, num_of_suspects);


        /// LOGS
        vector<CSHLog> log_vec_normal;
        vector<CSHLog> log_vec_suspicious;
        vector<CSHLog> log_vec_output;


        /// CREATE NORMAL LOGS
        log_vec_normal.reserve(num_of_normal_logs);
        for (int i=0; i<num_of_normal_logs; ++i)
        {
            log_vec_normal.push_back(generate_log(begin_date, end_date, begin_time, end_time, normal_ips, devices, methods, gen, true));
        }


        /// CREATE SUSPICIOUS LOGS
        log_vec_suspicious.reserve(num_of_suspicious_logs);
        for (int i=0; i<num_of_suspicious_logs; ++i)
        {
            log_vec_suspicious.push_back(generate_log(begin_date, end_date, begin_time, end_time, suspect_ips, devices, methods, gen, false));
        }



        /// COMBINE TWO LOGS
        /// AND SORT
        log_vec_output.reserve(log_vec_normal.size() + log_vec_output.size());
        log_vec_output.insert(log_vec_output.end(), log_vec_normal.begin(), log_vec_normal.end());
        log_vec_output.insert(log_vec_output.end(), log_vec_suspicious.begin(), log_vec_suspicious.end());
        sort(log_vec_output.begin(), log_vec_output.end());


        /// PUT LOG TO FILE
        //logs.open(argv[1]);
        //char filename[100];
        //sprintf(filename, "%04d%02d%02d-%04d%02d%02d.log", begin_date.year, begin_date.month, begin_date.day, end_date.year, end_date.month, end_date.day);
        logs.open(company_name);
        for (auto it=log_vec_output.begin(); it!=log_vec_output.end(); ++it)
        {
            logs << (*it) << endl;
        }
        logs.close();

        cout << "--- 로그 출력 완료 ---" << endl;
    }
    catch(const std::exception& e)
    {
        cout << "ERR: " << e.what() << endl;
    }

    return 0;
}


///
/// FUNCTION DEFINITIONS
///
CSHDate generate_date(const CSHDate& begin_date, const CSHDate& end_date)
{
    CSHDate dt;
    if (begin_date.year < end_date.year)
    {
        dt.year = begin_date.year + (rand() % (begin_date.year - end_date.year + 1));
        if (dt.year == end_date.year)
        {
            if (end_date.month == 1)
                dt.month = 1;
            else
                dt.month = (rand() % end_date.month) + 1;

            if (dt.month == end_date.month)
                dt.day = (rand() % end_date.day) + 1;
            else
                dt.day = rand()%30 + 1;
        }
        else if (dt.year == begin_date.year)
        {
            if (begin_date.month == 12)
                dt.month = 12;
            else
                dt.month = begin_date.month + (rand() % (12 - begin_date.month + 1));

            if (dt.month == begin_date.month)
                dt.day = begin_date.day + (rand() % (30 - begin_date.day + 1));
            else
                dt.day = rand()%30 + 1;
        }
        else
        {
            dt.month = rand()%12 + 1;
            dt.day = rand()%30 + 1;
        }
    }
    else    /// begin_date.year == end_date.year
    {
        dt.year = begin_date.year;

        if (begin_date.month == end_date.month)
        {
            dt.month = begin_date.month;
            if (begin_date.day == end_date.day)
                dt.day = begin_date.day;
            else
                dt.day = begin_date.day + (rand() % (end_date.day - begin_date.day + 1));
        }
        else
        {
            dt.month = begin_date.month + (rand() % (end_date.month - begin_date.month + 1));
            if (dt.month == begin_date.month)
                dt.day = begin_date.day + (rand() % (30 - begin_date.day + 1));
            else if (dt.month == end_date.month)
                dt.day = (rand() % end_date.day) + 1;
            else
                dt.day = rand()%30 + 1;
        }
    }

    return dt;
}

CSHTime generate_time(const CSHTime& normal_begin_time, const CSHTime& normal_end_time, bool is_normal, mt19937& gen)
{
    CSHTime ti;

    int time_diff = (normal_end_time.hour*3600 + normal_end_time.min*60 + normal_end_time.sec) - (normal_begin_time.hour*3600 + normal_begin_time.min*60 + normal_begin_time.sec);
    int begin_time_seconds = (normal_begin_time.hour*3600 + normal_begin_time.min*60 + normal_begin_time.sec);
    if (is_normal)
    {
        int normal_timestamp = begin_time_seconds;
        //normal_timestamp += (rand() % time_diff);
        uniform_int_distribution<> dis(0, time_diff+1);
        normal_timestamp += dis(gen);

        ti.hour = normal_timestamp/3600;
        normal_timestamp %= 3600;

        ti.min = normal_timestamp/60;
        normal_timestamp %= 60;

        ti.sec = normal_timestamp;
    }
    else
    {
        /// ----------------
        /// |     ||||||   |
        /// ----------------
        /// ^     ^    ^   ^
        /// p1    p2   p3  p4
        ///
        /// 정상 시간 --> p2~p3 (time_diff)
        /// 랜덤하게 만들어낸 시간이 p1~p2인지, p3~p4인지에 따라 p2~p3 사이 시간을 추가해야 함
        //int abnormal_timestamp = rand() % ((24*60*60) - time_diff + 1);
        // uniform_int_distribution<> dis(1, (24*60*60)-time_diff+1);
        // int abnormal_timestamp = dis(gen);
        // if (abnormal_timestamp >= begin_time_seconds)
        // {
        //     /// p3~p4
        //     abnormal_timestamp += time_diff;
        // }

        // ti.hour = abnormal_timestamp/3600;
        // abnormal_timestamp %= 3600;

        // ti.min = abnormal_timestamp/60;
        // abnormal_timestamp %= 60;

        // ti.sec = abnormal_timestamp;

        ti.hour = rand() % 24;
        ti.min = rand() % 60;
        ti.sec = rand() % 60;
    }

    return ti;
}

void generate_ips(vector<string>& normal_ips, vector<string>& suspect_ips, int num_of_normal_users, int num_of_suspects)
{
    //normal_ips.resize(num_of_normal_users);
    //suspect_ips.resize(num_of_suspects);

    string ip;
    for (int i=0; i<num_of_normal_users; ++i)
    {   
        ip = "";
        ip += to_string(rand() % 256);
        ip += ".";
        ip += to_string(rand() % 256);
        ip += ".";
        ip += to_string(rand() % 256);
        ip += ".";
        ip += to_string(rand() % 256);
        if (find(normal_ips.begin(), normal_ips.end(), ip) != normal_ips.end())
        {
            --i;
            continue;
        }
        normal_ips.push_back(ip);
    }

    for (int i=0; i<num_of_suspects; ++i)
    {
        ip = "";
        ip += to_string(rand() % 256);
        ip += ".";
        ip += to_string(rand() % 256);
        ip += ".";
        ip += to_string(rand() % 256);
        ip += ".";
        ip += to_string(rand() % 256);
        if (find(normal_ips.begin(), normal_ips.end(), ip) != normal_ips.end() || find(suspect_ips.begin(), suspect_ips.end(), ip) != suspect_ips.end())
        {
            --i;
            continue;
        }
        suspect_ips.push_back(ip);
    }
}

CSHLog generate_log(const CSHDate& begin_date, const CSHDate& end_date, const CSHTime& normal_begin_time, const CSHTime& normal_end_time, const vector<string>& ips, const vector<Device>& devices, const vector<char>& methods, mt19937& gen, bool is_normal)
{
    CSHLog lg;
    lg.timestamp_date = generate_date(begin_date, end_date);
    lg.timestamp_time = generate_time(normal_begin_time, normal_end_time, is_normal, gen);
    lg.ip = ips[ rand()%ips.size() ];

    Device dev = devices[ rand()%devices.size() ];
    lg.device_name = dev.name;
    uniform_int_distribution<ULL> dis(dev.min_usage, dev.max_usage);
    if (is_normal)
        lg.usage = dis(gen);
    else
        lg.usage = dev.max_usage*2 + dis(gen) * (rand()%10 + 1); //max*2 + rand의 1~10배


    lg.method = methods[ rand()%methods.size() ];

    // DEBUG
    // if (!is_normal)
    //     lg.device_name = "#########";
    return lg;
}

ostream& operator<<(ostream& os, const CSHDate& dt)
{
    os << dt.year << "-"
       << setw(2) << setfill('0') << dt.month << "-"
       << setw(2) << setfill('0') << dt.day;
    return os;
}

ostream& operator<<(ostream& os, const CSHTime& ti)
{
    os << setw(2) << setfill('0') << ti.hour << ":"
       << setw(2) << setfill('0') << ti.min << ":"
       << setw(2) << setfill('0') << ti.sec;
    return os;
}

ostream& operator<<(ostream& os, const CSHLog& lg)
{
    //FORMAT : [2016-08-04/23:09:13] [58.62.1.77] [printer1] [300] [c]
    os << "[" << lg.timestamp_date << "/" << lg.timestamp_time << "]"
       << " [" << lg.ip << "]"
       << " [" << lg.device_name << "]"
       << " [" << lg.usage << "]"
       << " [" << lg.method << "]";
    return os;
}
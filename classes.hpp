#pragma once

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
#include <stdexcept>
#include <string>
#include <vector>
using namespace std;

/// TYPEDEF
typedef unsigned long long ULL;

/// STRUCT DEFINITIONS
struct CSHDate
{
    int year;
    int month;
    int day;

    CSHDate() {}
    CSHDate(int _year, int _month, int _day)
        : year(_year), month(_month), day(_day)
    {
    }

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

    friend inline istream& operator>>(istream& in, CSHDate& dt)
    {
        in >> dt.year >> dt.month >> dt.day;
        return in;
    }

    friend inline ostream& operator<<(ostream& os, const CSHDate& dt)
    {
        os << dt.year << "-"
           << setw(2) << setfill('0') << dt.month << "-"
           << setw(2) << setfill('0') << dt.day;
        return os;
    }
};

struct CSHTime
{
    int hour;
    int min;
    int sec;

    CSHTime() {}
    CSHTime(int _hour, int _min, int _sec)
        : hour(_hour), min(_min), sec(_sec)
    {
    }

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

    friend inline istream& operator>>(istream& in, CSHTime& ti)
    {
        in >> ti.hour >> ti.min >> ti.sec;
        return in;
    }
    friend inline ostream& operator<<(ostream& os, const CSHTime& ti)
    {
        os << setw(2) << setfill('0') << ti.hour << ":"
           << setw(2) << setfill('0') << ti.min << ":"
           << setw(2) << setfill('0') << ti.sec;
        return os;
    }
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

    friend inline ostream& operator<<(ostream& os, const CSHLog& lg)
    {
        //FORMAT : [2016-08-04/23:09:13] [58.62.1.77] [printer1] [300] [c]
        os << "[" << lg.timestamp_date << "/" << lg.timestamp_time << "]"
           << " [" << lg.ip << "]"
           << " [" << lg.device_name << "]"
           << " [" << lg.usage << "]"
           << " [" << lg.method << "]";
        return os;
    }
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

struct Option
{
    string company_name;
    CSHDate begin_date, end_date;
    CSHTime begin_time, end_time;
    int num_of_normal_logs,
        num_of_suspicious_logs;
    int num_of_normal_users,
        num_of_suspects;
    int num_of_device_types;
    vector<Device> devices;
    vector<char> methods;

    friend inline istream& operator>>(istream& in, Option& op)
    {
        in >> op.company_name;
        in >> op.begin_date >> op.end_date;
        in >> op.begin_time >> op.end_time;
        in >> op.num_of_normal_users >> op.num_of_suspects
            >> op.num_of_device_types;

        string device_name;
        int num_of_devices;
        Device dev;
        for (int i=0; i<op.num_of_device_types; ++i)
        {
            in >> device_name >> num_of_devices >> dev.min_usage >> dev.max_usage;
            for (int j=0; j<num_of_devices; ++j)
            {
                dev.name = device_name + to_string(j+1);
                op.devices.push_back(dev);
            }
        }

        in >> op.num_of_normal_logs >> op.num_of_suspicious_logs;
        op.methods = {'C', 'R', 'U', 'D'};
        return in;
    }

    friend inline ostream& operator<<(ostream& os, const Option& op)
    {
        os << "--- settings ---" << endl;
        os << "시작~종료 일자:\t\t" << op.begin_date << " ~ " << op.end_date << endl;
        os << "정상 근무 시간:\t\t" << op.begin_time << " ~ " << op.end_time << endl;
        os << "비정상/일반 사용자 수:\t" << op.num_of_suspects << " / " << op.num_of_normal_users << endl;
        os << "비정상/정상로그:\t" << op.num_of_suspicious_logs << " / " << op.num_of_normal_logs << endl;
        os << "장치 종류 갯수:\t\t" << op.num_of_device_types;

        return os;
    }
};


struct LogGenerator
{
private:
    void generate_ips();
    CSHDate generate_date();
    CSHTime generate_time(bool is_normal, mt19937& gen);
    CSHLog generate_log(bool is_normal, mt19937& gen);


public:
    Option option;
    vector<string> normal_ips, suspect_ips;
    vector<CSHLog> logs;

    void generate_logs(mt19937& gen);
    void put(ostream& os);
};

void LogGenerator::generate_ips()
{
    int& num_of_normal_users = option.num_of_normal_users;
    int& num_of_suspects = option.num_of_suspects;

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

CSHDate LogGenerator::generate_date()
{
    CSHDate dt;
    CSHDate& begin_date = option.begin_date;
    CSHDate& end_date = option.end_date;

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
            {
                if (dt.month == 2)
                    dt.day = rand()%28 + 1;
                else
                    dt.day = rand()%30 + 1;
            }
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
            { 
                if (dt.month == 2)
                    dt.day = rand()%28 + 1;
                else
                    dt.day = rand()%30 + 1;
            }
        }
        else
        {
            dt.month = rand()%12 + 1;
            if (dt.month == 2)
                dt.day = rand()%28 + 1;
            else
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
            {
                if (dt.month == 2)
                    dt.day = rand()%28 + 1;
                else
                    dt.day = rand()%30 + 1;
            }
        }
    }

    return dt;
}

CSHTime LogGenerator::generate_time(bool is_normal, mt19937& gen)
{
    CSHTime ti;
    CSHTime& normal_begin_time = option.begin_time;
    CSHTime& normal_end_time = option.end_time;

    int time_diff = (normal_end_time.hour*3600 + normal_end_time.min*60 + normal_end_time.sec) - (normal_begin_time.hour*3600 + normal_begin_time.min*60 + normal_begin_time.sec);
    int begin_time_seconds = (normal_begin_time.hour*3600 + normal_begin_time.min*60 + normal_begin_time.sec);
    if (is_normal)
    {
        int normal_timestamp = begin_time_seconds;
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
        ti.hour = rand() % 24;
        ti.min = rand() % 60;
        ti.sec = rand() % 60;
    }

    return ti;
}

CSHLog LogGenerator::generate_log(bool is_normal, mt19937& gen)
{
    CSHLog lg;
    lg.timestamp_date = generate_date();
    lg.timestamp_time = generate_time(is_normal, gen);
    if (is_normal)
        lg.ip = normal_ips[ rand()%normal_ips.size() ];
    else
        lg.ip = suspect_ips[ rand()%suspect_ips.size() ];


    Device dev = option.devices[ rand()%option.devices.size() ];
    lg.device_name = dev.name;
    uniform_int_distribution<ULL> dis(dev.min_usage, dev.max_usage);
    if (is_normal)
        lg.usage = dis(gen);
    else
        lg.usage = dev.max_usage*2 + dis(gen) * (rand()%10 + 1); //max*2 + rand의 1~10배

    lg.method = option.methods[ rand()%option.methods.size() ];
    return lg;
}

void LogGenerator::generate_logs(mt19937& gen)
{
    generate_ips();

    logs.reserve(option.num_of_normal_logs + option.num_of_suspicious_logs);
    for (int i=0; i<option.num_of_normal_logs; ++i)
        logs.push_back(generate_log(true, gen));
    for (int i=0; i<option.num_of_suspicious_logs; ++i)
        logs.push_back(generate_log(false, gen));
    sort(logs.begin(), logs.end());
}

void LogGenerator::put(ostream& os)
{
    for (auto&& _log : logs)
        os << _log << endl;
}
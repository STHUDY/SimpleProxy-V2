#pragma once

#include "ThreadpoolSimple.hpp"

class ThreadpoolAutoCtrlByTime : public ThreadpoolSimple
{
private:
    bool is_shutdown = false;
    bool is_stop_add_mission = false;

    size_t max_thread_number = 0;
    size_t min_thread_number = 0;

    int submit_count = 0;

    int wait_time_ms = 0;
    int clear_thread_time_ms = 1000 * 60 * 10;
    int add_thread_step = 0;
    int duration_div_time_ms = 500;

    void *thread_pool_simple = nullptr;
    bool *mission_dorp_callback = nullptr;

    std::function<void(std::vector<std::any>)> mission_drop_callback;
    std::function<void(std::string)> worker_create_fail_callback;
    std::function<void(std::string)> manager_create_fail_callback;

    void managerThreadpool();

public:
    ThreadpoolAutoCtrlByTime();
    ThreadpoolAutoCtrlByTime(size_t minThreadNumber, size_t maxThreadNumber);

    void openOutputError();
    void closeOutputError();

    void setMaxThreadNumber(size_t maxThreadNumber);
    void setWaitTimeMs(int waitTimeMs);
    void setClearThreadTimeMs(int clearThreadTimeMs);
    void setMinThreadNumber(size_t minThreadNumber);
    void setStepAddThreadNumber(int stepAddThreadNumber);
    void setMissionDropCallback(std::function<void(std::vector<std::any>)> callback);
    void setWorkerCreateFailCallback(std::function<void(std::string)> callback);
    void setManagerCreateFailCallback(std::function<void(std::string)> callback);

    void init();

    void shutdown(bool isForce = false);
    void waitMissionDone();

    template <typename F, typename... Args>
    bool submitMission(F &&task, Args &&...args);

    ~ThreadpoolAutoCtrlByTime();

protected:
    void errorCallback(int type, std::string info) override
    {
        if (type == 0x0001)
        {
            if (worker_create_fail_callback)
                worker_create_fail_callback(info);
        }
        else if (type == 0x0002)
        {
            ThreadpoolSimple::MissionBase *mission = ThreadpoolSimple::getAndPopMission();
            if (mission != nullptr)
            {
                auto args = mission->getArgsAsAny();

                if (mission_drop_callback)
                {
                    mission_drop_callback(args);
                }

                delete mission;
            }
        }
        else if (type == 0xFF01)
        {
            if (manager_create_fail_callback)
                manager_create_fail_callback(info);
        }
    }
};

template <typename F, typename... Args>
inline bool ThreadpoolAutoCtrlByTime::submitMission(F &&task, Args &&...args)
{
    if (this->is_stop_add_mission)
    {
        return false;
    }
    this->submit_count++;
    return ThreadpoolSimple::pushMission(task, args...);
}

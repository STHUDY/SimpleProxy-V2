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

    void *thread_pool_simple = nullptr;
    bool *mission_dorp_callback = nullptr;

    std::function<void(std::vector<std::any>)> mission_drop_callback;

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

    void init();

    void shutdown(bool isForce = false);
    void waitMissionDone();

    template <typename F, typename... Args>
    bool submitMission(F &&task, Args &&...args);

    ~ThreadpoolAutoCtrlByTime();

protected:
    void createWorkThreadErrorCallback() override
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

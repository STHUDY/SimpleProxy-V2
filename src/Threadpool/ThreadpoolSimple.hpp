#pragma once

#include <iostream>
#include <list>
#include <thread>
#include <functional>
#include <mutex>
#include <condition_variable>
#include <tuple>
#include <any>

class ThreadpoolSimple
{
protected:
    struct WorkAttribute
    {
        std::thread *thread;
        bool isClosed;
    };

    struct MissionBase
    {
        virtual ~MissionBase() = default;
        virtual void execute() = 0;
        virtual std::vector<std::any> getArgsAsAny() const = 0;
    };

    template <typename... Args>
    struct Mission : MissionBase
    {
        std::function<void(Args...)> task;
        std::tuple<std::decay_t<Args>...> arguments;

        template <typename F>
        Mission(F &&f, Args &&...args)
            : task(std::forward<F>(f)),
              arguments(std::forward<Args>(args)...) {}

        void execute() override
        {
            std::apply(task, arguments);
        }

        std::vector<std::any> getArgsAsAny() const override
        {
            std::vector<std::any> result;
            std::apply([&](auto &&...args)
                       {
            // 展开参数并存入 any
            ((result.push_back(std::any(args))), ...); }, arguments);
            return result;
        }
    };

private:
    bool threadpool_is_close = false;
    bool is_can_submit_mission = true;
    bool is_finish_destroy = true;
    bool is_output_error = false;

    size_t pool_size = 0;
    size_t working_thread_number = 0;
    size_t free_thread_number = 0;
    size_t busy_thread_number = 0;
    size_t wait_destroy_number = 0;

    std::mutex mission_list_mutex;
    std::mutex work_count_mutex;
    std::mutex work_mutex;
    std::mutex manager_mutex;

    std::condition_variable cv_work;
    std::condition_variable cv_manager;

    std::thread *manager_thread;

    std::list<WorkAttribute *> work_thread_list;

    std::list<MissionBase *> mission_list;

    void createManagerThread();
    void createWorkThread();

    template <typename F, typename... Args>
    void createMission(F &&task, Args &&...args);

    void clearDestroyThread();

    void assignMissions();

public:
    ThreadpoolSimple();
    ThreadpoolSimple(size_t poolSize);

    void setPoolSize(size_t poolSize);
    void openOutputError();
    void closeOutputError();
    void notifyManagerThread();

    template <typename F, typename... Args>
    bool pushMission(F &&task, Args &&...args);
    bool popMission();
    MissionBase *getAndPopMission();
    void clearMissions();

    void sthutdown();

    size_t getPoolSize();
    size_t getBusyThreadNumber();
    size_t getFreeThreadNumber();
    size_t getMissionNumber();

    ~ThreadpoolSimple();

protected:
    virtual void createWorkThreadErrorCallback(void)
    {
        return;
    }
};

template <typename F, typename... Args>
void ThreadpoolSimple::createMission(F &&task, Args &&...args)
{
    using TaskType = std::function<void(Args...)>;
    auto mission = new Mission<Args...>(
        TaskType(std::forward<F>(task)),
        std::forward<Args>(args)...);

    std::lock_guard<std::mutex> lock(mission_list_mutex);
    mission_list.push_back(mission);
}

template <typename F, typename... Args>
inline bool ThreadpoolSimple::pushMission(F &&task, Args &&...args)
{
    if (this->is_can_submit_mission)
    {
        this->createMission(task, args...);
        this->notifyManagerThread();
    }
    return this->is_can_submit_mission;
}

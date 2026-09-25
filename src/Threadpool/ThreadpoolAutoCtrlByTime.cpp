#include "ThreadpoolAutoCtrlByTime.hpp"

void ThreadpoolAutoCtrlByTime::managerThreadpool()
{
    auto lastAdjustTime = std::chrono::steady_clock::now();
    size_t lastPoolSize = ThreadpoolSimple::getPoolSize();
    auto waitLastTime = std::chrono::steady_clock::now();
    size_t timeout = 0;

    while (!this->is_shutdown)
    {
        const size_t poolSize = ThreadpoolSimple::getPoolSize();
        const size_t busyThreads = ThreadpoolSimple::getBusyThreadNumber();
        const size_t freeThreads = ThreadpoolSimple::getFreeThreadNumber();
        const size_t pendingMissions = ThreadpoolSimple::getMissionNumber();
        const auto now = std::chrono::steady_clock::now();

        if (this->wait_time_ms <= 0)
        {
            timeout = std::chrono::duration_cast<std::chrono::microseconds>(now - waitLastTime).count();
            timeout %= this->duration_div_time_ms;
            if (timeout == 0)
            {
                timeout = 10;
            }
        }
        else
            timeout = this->wait_time_ms;

        if (poolSize < this->min_thread_number)
        {
            ThreadpoolSimple::setPoolSize(this->min_thread_number);
            lastAdjustTime = now;
            std::this_thread::sleep_for(std::chrono::milliseconds(timeout));
            waitLastTime = now;
            continue;
        }
        else if (poolSize > this->max_thread_number)
        {
            ThreadpoolSimple::setPoolSize(this->max_thread_number);
            lastAdjustTime = now;
            std::this_thread::sleep_for(std::chrono::milliseconds(timeout));
            waitLastTime = now;
            continue;
        }

        if (pendingMissions > freeThreads)
        {
            // 总需求：正在忙的线程 + 等待处理的任务
            const size_t totalDemand = busyThreads + pendingMissions;

            // 距离满足需求还差多少线程
            // pendingMissions > freeThreads 时，通常 needIncrease > 0
            const size_t needIncrease = totalDemand > poolSize
                                            ? totalDemand - poolSize
                                            : 0;

            size_t increase = 0;

            if (this->add_thread_step > 0)
            {
                // 固定步长扩容，但不要超过实际缺口
                increase = std::min(needIncrease, static_cast<size_t>(this->add_thread_step));
            }
            else
            {
                // 没配置步长时，按待处理任务量的一半扩容，至少加 1 个
                increase = std::min(
                    needIncrease,
                    std::max<size_t>(1, pendingMissions / 2));
            }

            size_t targetThreads = std::min(
                this->max_thread_number,
                poolSize + increase);

            // 扩容分支不允许减少线程数
            targetThreads = std::max(targetThreads, poolSize);

            if (targetThreads != poolSize)
            {
                ThreadpoolSimple::setPoolSize(targetThreads);
                lastAdjustTime = now;
            }

            // 有任务积压时，不要进入后面的缩容逻辑
            std::this_thread::sleep_for(std::chrono::milliseconds(timeout));
            continue;
        }

        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastAdjustTime);
        if (elapsed.count() > this->clear_thread_time_ms)
        {
            const size_t idleThreads = poolSize - busyThreads;

            if (idleThreads > this->min_thread_number)
            {
                const size_t targetSize = std::max(
                    this->min_thread_number,
                    poolSize - (idleThreads / (pendingMissions == 0 ? 1 : pendingMissions)));

                if (targetSize != poolSize)
                {
                    ThreadpoolSimple::setPoolSize(targetSize);
                    lastAdjustTime = now;
                }
            }
        }

        if (poolSize == lastPoolSize && pendingMissions == 0)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(timeout * 2));
        }
        else
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(timeout));
        }

        waitLastTime = now;
        lastPoolSize = poolSize;
    }
}

ThreadpoolAutoCtrlByTime::ThreadpoolAutoCtrlByTime()
{
    this->is_shutdown = false;
}

ThreadpoolAutoCtrlByTime::ThreadpoolAutoCtrlByTime(size_t minThreadNumber, size_t maxThreadNumber) : min_thread_number(minThreadNumber + 1), max_thread_number(maxThreadNumber + 1)
{
    this->is_shutdown = false;
    this->init();
}

void ThreadpoolAutoCtrlByTime::openOutputError()
{
    ThreadpoolSimple::openOutputError();
}

void ThreadpoolAutoCtrlByTime::closeOutputError()
{
    ThreadpoolSimple::closeOutputError();
}

void ThreadpoolAutoCtrlByTime::setMaxThreadNumber(size_t maxThreadNumber)
{
    this->max_thread_number = maxThreadNumber + 1;
    if (this->max_thread_number < this->min_thread_number)
    {
        this->max_thread_number = this->min_thread_number;
    }
}

void ThreadpoolAutoCtrlByTime::setWaitTimeMs(int waitTimeMs)
{
    this->wait_time_ms = waitTimeMs;
}

void ThreadpoolAutoCtrlByTime::setClearThreadTimeMs(int clearThreadTimeMs)
{
    this->clear_thread_time_ms = clearThreadTimeMs;
}

void ThreadpoolAutoCtrlByTime::setMinThreadNumber(size_t minThreadNumber)
{
    this->min_thread_number = minThreadNumber + 1;
    if (this->min_thread_number > this->max_thread_number)
    {
        this->min_thread_number = this->max_thread_number;
    }
}

void ThreadpoolAutoCtrlByTime::setStepAddThreadNumber(int stepAddThreadNumber)
{
    this->add_thread_step = stepAddThreadNumber;
}

void ThreadpoolAutoCtrlByTime::setMissionDropCallback(std::function<void(std::vector<std::any>)> callback)
{
    this->mission_drop_callback = std::move(callback);
}

void ThreadpoolAutoCtrlByTime::setWorkerCreateFailCallback(std::function<void(std::string)> callback)
{
    this->worker_create_fail_callback = callback;
}

void ThreadpoolAutoCtrlByTime::setManagerCreateFailCallback(std::function<void(std::string)> callback)
{
    this->manager_create_fail_callback = callback;
}

void ThreadpoolAutoCtrlByTime::init()
{
    ThreadpoolSimple::setPoolSize(this->min_thread_number + 1);
    ThreadpoolSimple::pushMission([this]()
                                  { this->managerThreadpool(); });
}

void ThreadpoolAutoCtrlByTime::shutdown(bool isForce)
{
    if (!isForce)
    {
        this->waitMissionDone();
    }
    this->is_shutdown = true;
    ThreadpoolSimple::sthutdown();
}

void ThreadpoolAutoCtrlByTime::waitMissionDone()
{
    this->is_stop_add_mission = true;
    auto waitLastTime = std::chrono::steady_clock::now();
    size_t timeout = 0;
    while (ThreadpoolSimple::getMissionNumber() > 0 || ThreadpoolSimple::getBusyThreadNumber() > 1)
    {
        const auto now = std::chrono::steady_clock::now();
        if (this->wait_time_ms <= 0)
        {
            timeout = std::chrono::duration_cast<std::chrono::microseconds>(now - waitLastTime).count();
            timeout %= this->duration_div_time_ms;
            if (timeout == 0)
            {
                timeout = 10;
            }
        }
        else
            timeout = this->wait_time_ms;
        std::this_thread::sleep_for(std::chrono::milliseconds(timeout));
    }
    this->is_stop_add_mission = false;
}

ThreadpoolAutoCtrlByTime::~ThreadpoolAutoCtrlByTime()
{
    if (!this->is_shutdown)
        this->shutdown();
}

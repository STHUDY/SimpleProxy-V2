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
            timeout = std::chrono::duration_cast<std::chrono::microseconds>(now - waitLastTime).count() % 500;
            if (timeout == 0)
            {
                timeout = 1;
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
            size_t targetThreads = poolSize;
            const size_t requiredThreads = std::min(
                busyThreads + pendingMissions,
                this->max_thread_number);

            if (this->add_thread_step > 0)
            {
                targetThreads += this->add_thread_step;
                targetThreads = std::min(targetThreads, this->max_thread_number);
            }
            else
            {
                targetThreads += std::min(busyThreads, pendingMissions / 2);
                targetThreads = std::min(targetThreads, this->max_thread_number);
            }

            if (targetThreads != poolSize)
            {
                ThreadpoolSimple::setPoolSize(targetThreads);
                lastAdjustTime = now;
                std::this_thread::sleep_for(std::chrono::milliseconds(timeout));
                continue;
            }
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
    mission_drop_callback = std::move(callback);
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
            timeout = std::chrono::duration_cast<std::chrono::microseconds>(now - waitLastTime).count() % 500;
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

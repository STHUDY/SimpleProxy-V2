#include "ThreadpoolSimple.hpp"

void ThreadpoolSimple::createManagerThread()
{
    try
    {
        this->manager_thread = new std::thread(
            [this]()
            {
                this->is_can_submit_mission = true;
                size_t mission_count = 0;
                while (!this->threadpool_is_close)
                {
                    if (this->pool_size > this->working_thread_number)
                    {
                        size_t create_work_number = this->pool_size - this->working_thread_number;
                        for (size_t i = 0; i < create_work_number; i++)
                        {
                            if (!this->threadpool_is_close)
                            {
                                try
                                {
                                    this->createWorkThread();
                                }
                                catch (const std::exception &e)
                                {
                                    if (this->is_output_error)
                                        std::cerr << e.what() << '\n';
                                    this->pool_size -= 1;
                                    this->createWorkThreadErrorCallback();
                                }

                                this->assignMissions();
                            }
                        }
                    }

                    {
                        std::unique_lock<std::mutex> lockList(this->mission_list_mutex);
                        mission_count = this->mission_list.size();
                    }
                    if (mission_count == 0 && !this->threadpool_is_close)
                    {
                        std::unique_lock<std::mutex> lockManager(this->manager_mutex);
                        this->cv_manager.wait(lockManager);
                    }

                    this->assignMissions();

                    if (this->is_finish_destroy)
                        if (this->wait_destroy_number != 0)
                        {
                            {
                                std::unique_lock<std::mutex> lockCount(this->work_count_mutex);
                                this->is_finish_destroy = false;
                                this->createMission(
                                    [this]()
                                    { this->clearDestroyThread(); });
                            }
                        }
                }
            });
    }
    catch (const std::exception &e)
    {
        if (this->is_output_error)
        {
            std::cout << "ManagerThreadCreateError: " << e.what() << std::endl;
        }

        throw e;
    }
}

void ThreadpoolSimple::createWorkThread()
{
    {
        std::unique_lock<std::mutex> lock(this->work_count_mutex);
        this->working_thread_number += 1;
    }

    WorkAttribute *workAttribute = nullptr;

    try
    {
        workAttribute = new WorkAttribute();
        workAttribute->isClosed = false;
    }
    catch (const std::exception &e)
    {
        {
            std::unique_lock<std::mutex> lock(this->work_count_mutex);
            this->working_thread_number -= 1;
        }

        if (this->is_output_error)
        {
            std::cout << "WorkMemoryAllocError: " << e.what() << std::endl;
        }

        throw e;
    }

    try
    {
        std::thread *workThread = new std::thread(
            [this, workAttribute]()
            {
                while (!this->threadpool_is_close)
                {
                    {
                        {
                            std::unique_lock<std::mutex> lock(this->work_count_mutex);
                            this->free_thread_number += 1;
                        }

                        std::unique_lock<std::mutex> lockWork(this->work_mutex);
                        this->cv_work.wait(lockWork);

                        {
                            std::unique_lock<std::mutex> lockCount(this->work_count_mutex);
                            if (pool_size < working_thread_number)
                            {
                                this->free_thread_number -= 1;
                                break;
                            }
                            this->free_thread_number -= 1;
                            this->busy_thread_number += 1;
                        }
                    }

                    MissionBase *mission = nullptr;
                    {
                        std::unique_lock<std::mutex> lockList(this->mission_list_mutex);
                        if (!this->mission_list.empty())
                        {
                            mission = this->mission_list.front();
                            this->mission_list.pop_front();
                        }
                    }

                    if (mission != nullptr)
                    {
                        try
                        {
                            mission->execute();
                        }
                        catch (const std::exception &e)
                        {
                            if (this->is_output_error)
                            {
                                std::cout << "MissionError: " << e.what() << std::endl;
                            }
                        }
                        delete mission;
                        this->notifyManagerThread();
                    }

                    {
                        std::unique_lock<std::mutex> lockCount(this->work_count_mutex);
                        this->busy_thread_number -= 1;
                    }
                }

                if (this->threadpool_is_close)
                {
                    return;
                }

                {
                    std::unique_lock<std::mutex> lockCount(this->work_count_mutex);
                    this->working_thread_number -= 1;
                    this->wait_destroy_number += 1;
                    workAttribute->isClosed = true;
                }
            });

        workAttribute->thread = workThread;
        this->work_thread_list.push_back(workAttribute);
    }
    catch (const std::exception &e)
    {
        delete workAttribute;
        {
            std::unique_lock<std::mutex> lock(this->work_count_mutex);
            this->working_thread_number -= 1;
        }

        if (this->is_output_error)
        {
            std::cout << "WorkThreadCreateError: " << e.what() << std::endl;
        }

        throw e;
    }
}

void ThreadpoolSimple::clearDestroyThread()
{
    for (auto it = this->work_thread_list.begin();
         it != this->work_thread_list.end();)
    {
        if ((*it)->isClosed)
        {
            {
                std::unique_lock<std::mutex> lockCount(this->work_count_mutex);
                (*it)->thread->join();
                delete *it;
                it = this->work_thread_list.erase(it);
                this->wait_destroy_number--;
            }
        }
        else
        {
            ++it;
        }
    }
    {
        std::unique_lock<std::mutex> lockCount(this->work_count_mutex);
        this->is_finish_destroy = true;
    }
}

void ThreadpoolSimple::assignMissions()
{
    size_t mission_count = 0;
    {
        std::unique_lock<std::mutex> lockList(this->mission_list_mutex);
        mission_count = this->mission_list.size();
        if (mission_count > this->free_thread_number)
        {
            mission_count = this->free_thread_number;
        }
    }

    for (size_t i = 0; i < mission_count; i++)
    {
        cv_work.notify_one();
    }
}

ThreadpoolSimple::ThreadpoolSimple()
{
    createManagerThread();
};

ThreadpoolSimple::ThreadpoolSimple(size_t poolSize) : pool_size(poolSize)
{
    createManagerThread();
}

void ThreadpoolSimple::setPoolSize(size_t poolSize)
{
    this->pool_size = poolSize;
    this->notifyManagerThread();
}

void ThreadpoolSimple::openOutputError()
{
    this->is_output_error = true;
}

void ThreadpoolSimple::closeOutputError()
{
    this->is_output_error = false;
}

void ThreadpoolSimple::notifyManagerThread()
{
    std::unique_lock<std::mutex> lockManager(this->manager_mutex);
    this->cv_manager.notify_one();
}

bool ThreadpoolSimple::popMission()
{
    std::unique_lock<std::mutex> lock(this->mission_list_mutex);
    if (this->mission_list.empty())
    {
        return true;
    }
    MissionBase *mission = this->mission_list.back();
    this->mission_list.pop_back();
    delete mission;
    size_t mission_count = this->mission_list.size();
    return mission_count == 0 ? true : false;
}

ThreadpoolSimple::MissionBase * ThreadpoolSimple::getAndPopMission()
{
    std::unique_lock<std::mutex> lock(this->mission_list_mutex);

    if (this->mission_list.empty())
    {
        return nullptr;
    }

    MissionBase *mission = this->mission_list.back();
    this->mission_list.pop_back();
    return mission;
}

void ThreadpoolSimple::clearMissions()
{
    std::unique_lock<std::mutex> lock(mission_list_mutex);
    for (auto *mission : mission_list)
    {
        delete mission;
    }
    mission_list.clear();
}

void ThreadpoolSimple::sthutdown()
{
    this->threadpool_is_close = true;
    {
        std::unique_lock<std::mutex> lock(this->mission_list_mutex);
        this->is_can_submit_mission = false;
    }
    this->notifyManagerThread();
    if (this->manager_thread != nullptr)
    {
        this->manager_thread->join();
        delete this->manager_thread;
    }
    this->cv_work.notify_all();
    for (auto it : this->work_thread_list)
    {
        it->thread->join();
        delete it;
    }
    this->work_thread_list.clear();
}

size_t ThreadpoolSimple::getPoolSize()
{
    return this->pool_size;
}

size_t ThreadpoolSimple::getBusyThreadNumber()
{
    return this->busy_thread_number;
}

size_t ThreadpoolSimple::getFreeThreadNumber()
{
    return this->free_thread_number;
}

size_t ThreadpoolSimple::getMissionNumber()
{
    std::unique_lock<std::mutex> lockList(this->mission_list_mutex);
    return this->mission_list.size();
}

ThreadpoolSimple::~ThreadpoolSimple()
{
    if (!this->threadpool_is_close)
        this->sthutdown();
};

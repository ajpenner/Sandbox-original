/**
 * @file IpcService.hpp
 * Implementation file for qpid proton IPC services.
 *
 * @author Vijaya Arroju
 *
 * Derived from: qpid proton c++ examples , modified to fit 
 * into single thread handling with queue management
 *
 * PUBLIC INTERFACE : clients should ONLY use class IpcService {}
 * methods to access IPC services and SHOULD NOT USE any other classes
 * from this file.
 * 
 *
 * © 2019 Domino Printing Sciences Limited
 */

#ifndef IPCSERVICE_HPP
#define IPCSERVICE_HPP

#include <proton/connection.hpp>
#include <proton/connection_options.hpp>
#include <proton/container.hpp>
#include <proton/message.hpp>
#include <proton/messaging_handler.hpp>
#include <proton/receiver.hpp>
#include <proton/receiver_options.hpp>
#include <proton/sender_options.hpp>
#include <proton/sender.hpp>
#include <proton/work_queue.hpp>
#include <atomic>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <queue>
#include <sstream>
#include <string>
#include <thread>
#include <memory>
#include <sys/eventfd.h>

#include <Poco/Runnable.h>
#include "Poco/Thread.h"

static const size_t MAX_BUFFER = 100; // Max number of buffered messages

// Lock output from threads to avoid scrambling
//std::mutex out_lock;
//#define OUT(x) do { std::lock_guard<std::mutex> l(out_lock); x; } while (false)
// Exception raised if a sender or receiver is closed when trying to send/receive
class closed : public std::runtime_error {
public:
    closed(const std::string& msg) : std::runtime_error(msg) {}
};

/*
 * Class ProtonSender {} : NOT FOR CLIENTS USE.
 * Class to manage sending messages requests on AMQP topic
 */
class ProtonSender : public proton::messaging_handler {
    // Only used in proton handler thread
    proton::sender sender_;
    // Shared by proton and user threads, protected by lock_
    std::mutex lock_;
    proton::work_queue *work_queue_;
    std::condition_variable sender_ready_;
    std::queue<proton::message> buffer_; // Messages not yet returned by receive()
    int queued_;                       // Queued messages waiting to be sent
    int credit_;                       // AMQP credit - number of messages we can send
public:
    explicit ProtonSender()
        : work_queue_(0), queued_(0),credit_(0)
    {}

    // Thread safe
    bool send(const proton::message& m) {
        {
            std::unique_lock<std::mutex> l(lock_);
            // discard the messages if sender link is not established or
            // buffer is full with no sender credits
            if (!work_queue_ || (!credit_ && (buffer_.size() == MAX_BUFFER)))
                return false;
            buffer_.push(m);
        }
        work_queue_->add([=]() {
            this->do_send();
        }); // work_queue_ is thread safe
        return true;
    }

    // Thread safe
    void close() {
        work_queue()->add([=]() {
            sender_.connection().close();
        });
    }

    proton::work_queue* work_queue() {
        // Wait till work_queue_ and sender_ are initialized.
        std::unique_lock<std::mutex> l(lock_);
        while (!work_queue_) sender_ready_.wait(l);
        return work_queue_;
    }

    // == messaging_handler overrides, only called in proton handler thread
    void on_sender_open(proton::sender& s) override {
        // Make sure sender_ and work_queue_ are set atomically
        std::lock_guard<std::mutex> l(lock_);
        sender_ = s;
        work_queue_ = &s.work_queue();
    }

    // called when credits available to send 
    void on_sendable(proton::sender& s) override {
        std::lock_guard<std::mutex> l(lock_);
        credit_ = s.credit();
        sender_ready_.notify_all(); // Notify senders we have credit
    }

    // work_queue work items is are automatically dequeued and called by proton
    // This function is called because it was queued by send()
    void do_send() {
        std::lock_guard<std::mutex> l(lock_);
        while ((buffer_.size() > 0) && (sender_.credit() > 0))
        {
            proton::message m = std::move(buffer_.front());
            buffer_.pop();
            sender_.send(m);
            credit_ = sender_.credit();   // update credit
        }
        sender_ready_.notify_all();       // Notify senders we have space on queue
    }

    void on_error(const proton::error_condition& e) override {
        //OUT(std::cerr << "unexpected error: " << e << std::endl);
        exit(1);
    }
};

/*
 * Class ProtonReceiver {} : NOT FOR CLIENTS USE.
 * Class to handle received messages on AMQP topic
 */
class ProtonReceiver : public proton::messaging_handler {
public:
    // Used in proton threads only
    proton::receiver receiver_;
    // Used in proton and user threads, protected by lock_
    std::mutex lock_;
    proton::work_queue* work_queue_;
    std::queue<proton::message> buffer_; // Messages not yet returned by receive()
    std::condition_variable can_receive_; // Notify receivers of messages
    bool closed_;
    int efd_;  // event fd used in epoll  
    // Connect to url
    explicit ProtonReceiver()
        : work_queue_(0), closed_(false)
    {
        efd_ = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (efd_ == -1)
            throw std::runtime_error("Unable to create event fd!!!");
    }

    // Get event file descriptor
    int get_efb ()
    {
        return efd_;
    }

    // Thread safe receive
    proton::message receive() {

        if (!closed_ && (!work_queue_ || buffer_.empty())) {
            //can_receive_.wait(l);
            proton::message m;
            m.durable(false);
            return m;
        }

        if (closed_) throw closed("receiver closed");

        std::unique_lock<std::mutex> l(lock_);
        proton::message m = std::move(buffer_.front());
        m.durable(true);
        buffer_.pop();
        // Add a lambda to the work queue to call receive_done().
        // This will tell the handler to add more credit.
        work_queue_->add([=]() {
            this->receive_done();
        });
        return m;
    }

    // Thread safe
    void close() {
        std::lock_guard<std::mutex> l(lock_);
        if (!closed_) {
            closed_ = true;
            can_receive_.notify_all();
            if (work_queue_) {
                work_queue_->add([this]() {
                    this->receiver_.connection().close();
                });
            }
        }
    }

    // ==== The following are called by proton threads only.
    void on_receiver_open(proton::receiver& r) override {
        receiver_ = r;
        std::lock_guard<std::mutex> l(lock_);
        work_queue_ = &receiver_.work_queue();
        receiver_.add_credit(MAX_BUFFER); // Buffer is empty, initial credit is the limit
    }

    void on_message(proton::delivery &d, proton::message &m) override {
        // Proton automatically reduces credit by 1 before calling on_message
        std::lock_guard<std::mutex> l(lock_);
        buffer_.push(m);
        can_receive_.notify_all();
        uint64_t u = buffer_.size();
        if (eventfd_write(efd_, u) < 0)
            std::cout << "ProtonReceiver::on_message failed to write to event. " << std::endl;
    }

    // called via work_queue
    void receive_done() {
        uint64_t u;
        eventfd_read(efd_, &u);
        // Add 1 credit, a receiver has taken a message out of the buffer.
        receiver_.add_credit(1);
    }
    void on_error(const proton::error_condition& e) override {
        //OUT(std::cerr << "unexpected error: " << e << std::endl);
        exit(1);
    }
};

/*
 * Class ProtonHandler {} : NOT FOR CLIENTS USE.
 * Class to handle qpid proton container callbacks
 */
class ProtonHandler : public proton::messaging_handler {
    std::string conn_url_ ;
    std::string sender_addr_;
    std::string receiver_addr_;


    ProtonReceiver receive_handler_;
    ProtonSender send_handler_;

public:
    explicit ProtonHandler(const std::string& s, const std::string& r) :
        conn_url_("127.0.0.1:5672"),
        sender_addr_(s),
        receiver_addr_(r),
        receive_handler_(),
        send_handler_()
    {}

    ProtonReceiver& Receiver()
    {
        return receive_handler_;
    }

    ProtonSender& Sender()
    {
        return send_handler_;
    }

    void on_container_start(proton::container& c) override {
        c.connect(conn_url_);
    }

    void on_connection_open(proton::connection& c) override {

        // create sender / receiver only if valid topic address passed
        if (sender_addr_.size() > 0)
        {
            proton::sender_options opts;
//        opts.delivery_mode(delivery_mode::AT_MOST_ONCE);
            opts.handler(send_handler_);
            c.open_sender(sender_addr_, opts);
        }

        if (receiver_addr_.size() > 0)
        {
           // NOTE:credit_window(0) disables automatic flow control.
           // We will use flow control to match AMQP credit to buffer capacity.
            proton::receiver_options opts;
            opts.handler(receive_handler_);
            opts.credit_window(0);
            c.open_receiver(receiver_addr_, opts);
        }
    }

};

/*
 * Class IpcRunnable {} : NOT FOR CLIENTS USE.
 * Runnable class to run container thread.
 */
class IpcRunnable : public Poco::Runnable
{
public:
    explicit IpcRunnable(const std::string& senderQ, const std::string& receiverQ) :
        m_senderQ{senderQ},
        m_receiverQ{receiverQ}
    {
        m_handler = std::make_unique<ProtonHandler>(m_senderQ, m_receiverQ);
        m_container = std::make_unique<proton::container>(*m_handler);

    }

    ~IpcRunnable()
    {
        if (m_handler)
        {
            m_handler->Sender().close();
            m_handler->Receiver().close();
        }

        if (m_container)
            m_container->stop();

        //      if (m_efd != -1)
        //         close(m_efd);
    }

    void run(void )
    {
        m_container->run();
    }

    bool SendMsg(const std::string& msg_body)
    {
        if (m_handler)
            return m_handler->Sender().send(proton::message(msg_body));
        return false;
    }

    bool DequeMsg(std::string& msg)
    {
        if (m_handler)
        {
            proton::message m = m_handler->Receiver().receive();
            if (m.durable())
            {
                msg = proton::coerce<std::string>(m.body());
                return true;
            }
        }
        return false;
    }

    int GetFd()
    {
        return m_handler->Receiver().get_efb();
    }

private:
    std::string m_senderQ;
    std::string m_receiverQ;

    std::unique_ptr<proton::container> m_container;
    std::unique_ptr<ProtonHandler> m_handler;

};

/*
 * PUBLIC INTERFACE FOR CLIENTS TO USE
 *
 * Class IpcService {}
 * This class is responsible to hide implementation details of
 * creating and managing qpid proton IPC links.
 *
 * Contructor take two arguments sender topic address and receiver topic address
 * ex: IpcService ipc{"examples_send","examples_rsv"};
 *
 * GetFd() : Method returns file handle to be used with epoll to wait for
 *           messages on receiver topic.
 *           NOTE : file handle should not be used for writing.
 *           Ex : struct epoll_event ev;
 *                ev.data.fd = ipc.GetFd();
 *                ev.events = EPOLLIN;
 *                const auto epfd = epoll_create(1);
 *                const auto res = epoll_ctl(epfd, EPOLL_CTL_ADD, ev.data.fd, &ev);
 * SendMsg() : Non blocking call to send messages on sender topic.
 *             Ex : std::string msg = "Test msg";
 *                  ipc.SendMsg(msg);
 * DequeMsg() : Non blocking call to receive messages on receiver topic.
 *              SHould be called only after receiving epoll event.
 *              Returns false when queue is empty, clients can loop on
 *              method to dequeue all messages in queue until method returns false.
 *              Ex : 
 *                  struct epoll_event event[1];
 *                  int res = epoll_wait(epfd, event, 1, 5000);
 *                  if (res) {
 *                     std::string msg;
 *                      while(ipc.DequeMsg(msg))
 *                      {
 *                         std::cout << "Received message : " << msg << std::endl;
 *                      }
 *                  }
 */
class IpcService
{

public:
    explicit IpcService(const std::string& senderQ, const std::string& receiverQ) :
        m_runnable(senderQ, receiverQ),
        m_thread{}
    {
        m_thread.start(m_runnable);
    }

    ~IpcService()
    {
        m_thread.join();
    }

    bool SendMsg(const std::string& msg)
    {
        return m_runnable.SendMsg(msg);
    }

    bool DequeMsg(std::string& msg)
    {
        return m_runnable.DequeMsg(msg);
    }

    int GetFd()
    {
        return m_runnable.GetFd();
    }

private:
    IpcRunnable m_runnable;
    Poco::Thread m_thread;
};

#endif

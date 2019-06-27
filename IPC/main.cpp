#include "IpcService.hpp"
#include <sys/epoll.h>
 
int main ()
{
    std::cout << "Main " << std::endl;
 
    {
       IpcService ipc{"examples_send","examples_rsv"};
       std::string msg = "Test msg";
       ipc.SendMsg(msg);
 
       struct epoll_event ev;
       ev.data.fd = ipc.GetFd();
       ev.events = EPOLLIN; // | EPOLLOUT;
       std::cout << " fd : " << ev.data.fd << std::endl;
       const auto epfd = epoll_create(1);
       epoll_ctl(epfd, EPOLL_CTL_ADD, ev.data.fd, &ev);
       struct epoll_event event[1];
 
       while(1)
       {
           int res = epoll_wait(epfd, event, 1, 5000);
           if (res) {
               std::string msg = "";
               while(ipc.DequeMsg(msg))
               {
                  std::cout << "Received : " << event[0].data.fd << " " << msg << std::endl;
               }
           }
       }
    }
 
    std::cout << "Main end" << std::endl;
    return 0;
}

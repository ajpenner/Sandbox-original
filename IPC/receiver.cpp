#include "IpcService.hpp"
#include <sys/epoll.h>
#include <unistd.h>
#include <sys/types.h>
#include <unistd.h>
 
int main ()
{
    std::cout << "Main " << std::endl;
 
    {
       IpcService ipc{"","examples_send"};
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
            std::cout << "I am trying" <<std::endl;
           int res = epoll_wait(epfd, event, 1, 250);
           if (res) {
               std::string msg = "";
//               sleep(1);
               while(ipc.DequeMsg(msg))
               {
                  std::cout << "PID " << getpid() << " Received : " << event[0].data.fd << " " << msg << std::endl;
               }
           }
       }
    }
 
    std::cout << "Main end" << std::endl;
    return 0;
}

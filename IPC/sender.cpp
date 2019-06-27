#include "IpcService.hpp"
#include <sys/epoll.h>
#include <sstream>
#include <iostream>
#include <string>
#include <sys/types.h>
#include <unistd.h>
 
int main ()
{
    std::cout << "Main " << std::endl;
 
    {
       IpcService ipc{"examples_send",""};
       std::string msg = "Test msg";
       ipc.SendMsg(msg);
 
       struct epoll_event ev;
       ev.data.fd = ipc.GetFd();
       ev.events = EPOLLIN; // | EPOLLOUT;
       std::cout << " fd : " << ev.data.fd << std::endl;
       const auto epfd = epoll_create(1);
       epoll_ctl(epfd, EPOLL_CTL_ADD, ev.data.fd, &ev);
       struct epoll_event event[1];
       int sent = 0;
 
       while(1)
       {
           int res = epoll_wait(epfd, event, 1, 250);
           if (res) {
               std::string msg = "";
               while(ipc.DequeMsg(msg))
               {
                  std::cout << "Received : " << event[0].data.fd << " " << msg << std::endl;
               }
           }
           else
           {
               std::ostringstream m;
               m << " PID " << getpid() <<  " send " << sent + 1 << std::endl;
               std::string st = m.str();
              bool r = ipc.SendMsg(st);
              std::cout << " PID " << getpid() << " Msg sent  "<< r << " " << st << std::endl;
              sent++;
           }
       }
    }
 
    std::cout << "Main end" << std::endl;
    return 0;
}

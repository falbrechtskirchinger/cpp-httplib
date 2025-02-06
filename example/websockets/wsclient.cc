//
//  wsclient.cc
//
//  Copyright (c) 2025 Florian Albrechtskirchinger. All rights reserved.
//  MIT License
//

#include "httplib-ws.h"

int main(void) {
  httplib::WebSocketClient cli{"ws://localhost:8080"};

  if (!cli.connect("/endpoint", httplib::Headers{}, httplib::WSSubprotocols{"echo"},
                   [](std::string msg, httplib::WSMessageType /*msg_type*/) {
                     std::cout << "Message received: " << msg << "\n";
                   })) {
    std::cout << "Failed to connect.\n";
    return 1;
  }

  if(cli.subprotocol_negotiated()) {
    std::cout << "Using subprotocol: " << cli.subprotocol() << "\n";
  }

  cli.send("Hello, WebSockets!");

  std::this_thread::sleep_for(std::chrono::seconds{3});

  cli.close();
  cli.wait_closed();

  return 0;
}

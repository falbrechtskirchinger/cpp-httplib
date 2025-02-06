//
//  wsserver.cc
//
//  Copyright (c) 2025 Florian Albrechtskirchinger. All rights reserved.
//  MIT License
//

#include "httplib-ws.h"

int main(void) {
  httplib::WebSocketServer svr;

  svr.WebSocket("/endpoint", [](httplib::WSConnection &connection, std::string msg, httplib::WSMessageType msg_type) {
    std::cout << "Message received: " << msg << "\n";
    connection.wait_until_ready();
    if(connection.send(std::move(msg), msg_type)) {
      std::cout << "Sucessfully echoed message!\n";
    }
  }, httplib::WSSubprotocols{"echo"});

  std::cout << "Listening on http://localhost:8080/\n";

  svr.listen("localhost", 8080);

  return 0;
}

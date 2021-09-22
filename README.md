# Zenoh Dissector
[Zenoh](http://zenoh.io/) protocol dissector for Wireshark.

![zenoh dissector banner](https://github.com/cguimaraes/zenoh-dissector/raw/master/zenoh-wireshark.png)

## Under development

- [x] Zenoh Messages
  - [x] Declare
      - [x] Resource Declaration
      - [x] Publisher Declaration
      - [x] Subscriber Declaration
      - [x] Queryable Declaration
      - [x] Forget Resource
      - [x] Forget Publisher
      - [x] Forget Subscriber
      - [x] Forget Queryable
  - [x] Data
  - [x] Query
  - [x] Pull
  - [x] Unit
  - [x] Link State List
- [x] Session Messages
  - [x] Scout
  - [x] Hello
  - [x] Init
  - [x] Join
  - [x] Open
  - [x] Close
  - [x] Sync
  - [x] Ack Nack
  - [x] Keep Alive
  - [x] Ping Pong
  - [x] Frame
- [x] Decorators Messages
  - [x] Priority
  - [x] Routing Context
  - [x] Reply Context
  - [x] Attachment
- [x] Decode Frame message (including several messages)
  - [x] Support Frame fragmentation
- [x] Decode multiple Zenoh messages in a single TCP message
  - [x] Handle Zenoh messages split across TCP messages
- [ ] Message filtering for framed messages
- [ ] Implement test suite (ongoing) 
- [ ] Extensive testing

## Usage

To use this, copy zenoh.lua to ~/.local/lib/wireshark/plugins.
Then when you run Wireshark it will understand TCP/UDP communications
on port 7447 as Zenoh messages, and will know how to interpret them. 

## License
This program and the accompanying materials are made available under the
terms of the Eclipse Public License 2.0 which is available at
http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
which is available at https://www.apache.org/licenses/LICENSE-2.0.

SPDX-License-Identifier: EPL-2.0 OR Apache-2.0

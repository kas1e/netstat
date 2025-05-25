# netstat
AmigaOS 4 netstat: Network monitoring with Roadshow API, replicating Unix output

**netstat** is a command-line utility for AmigaOS 4 that provides network diagnostics and connection tracking, replicating the output and functionality of the Unix `netstat` tool. Built using the Roadshow API from the `bsdsocket.library`, netstat displays TCP/UDP/ICMP connection statuses, interface metrics, routing tables, and protocol statistics. It supports key `netstat` options for cross-platform compatibility and is intended for educational purposes to demonstrate the use of the Roadshow API.

---

## Features

- Displays active TCP, UDP, and ICMP connections with their states (e.g., **LISTEN**, **ESTABLISHED**)
- Shows interface statistics (e.g., MTU, packet counts, errors)
- Outputs routing tables
- Supports IP, TCP, UDP, and ICMP protocol statistics
- Command-line options:
  - `-a` — show all connections
  - `-l` — show listening connections
  - `-n` — display numeric values
  - `-s` — show statistics
  - `-i` — list interfaces
  - `-r` — display routes
  - `--help` — view help
  - `--version` — check version

---

## Usage of Roadshow API

netstat leverages the following Roadshow API functions for network operations:

- **`ISocket->GetNetworkStatistics`** — retrieves detailed statistics for IP, TCP, UDP, and ICMP protocols for traffic analysis and debugging.
- **`ISocket->ObtainInterfaceList` / `ISocket->ReleaseInterfaceList`** — enumerates network interfaces and their metrics for system monitoring.
- **`ISocket->QueryInterfaceTags`** — extracts interface properties (e.g., MTU, packet counts) to populate the interface table.
- **`ISocket->socket` / `ISocket->send` / `ISocket->recv` / `ISocket->CloseSocket`** — manages the routing socket for querying and parsing routing table entries.
- **`ISocket->Inet_NtoA` / `ISocket->gethostbyaddr` / `ISocket->getservbyport`** — converts IP addresses and ports to human-readable names, toggleable with `-n`.
- **`ISocket->Errno`** — retrieves error codes after failed socket operations, enabling precise error reporting (e.g., for failed `GetNetworkStatistics` calls).
- **`ISocket->SocketBaseTags`** — queries the socket base for supported features, such as checking if `GetNetworkStatistics` is available, ensuring compatibility with the library version.

---

## Installation and Usage

1. **Requirements**: AmigaOS 4 SDK with `bsdsocket.library` version 4+.
2. **Build**: Compile using `gcc netstat.c -o netstat`.
3. **Run**: Execute `netstat [options]`, e.g., `netstat -a` to display all connections.

---

## Educational Purpose

This code is provided for educational purposes to demonstrate how to use the Roadshow API for network diagnostics on AmigaOS 4. It serves as a practical example of working with the `bsdsocket.library` for developers interested in AmigaOS networking features.

---

## License

MIT License

Copyright (c) 2025 kas1e

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND...

---


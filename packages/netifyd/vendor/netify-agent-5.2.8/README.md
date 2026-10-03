# Netify Agent
[https://www.netify.ai](https://www.netify.ai)

Copyright ©2015-2026 eGloo Incorporated ([www.egloo.ca](https://www.egloo.ca))

CI Status: [![pipeline status](https://gitlab.com/netify.ai/public/netify-agent/badges/master/pipeline.svg)](https://gitlab.com/netify.ai/public/netify-agent/-/commits/master)

## Overview
The **Netify Agent** is a high-performance, multi-threaded passive network traffic analyzer that leverages deep-packet inspection (DPI) to identify network protocols and applications. Built on top of [nDPI](https://github.com/ntop/nDPI), it is designed to provide comprehensive network visibility by capturing traffic from multiple internal (LAN) and external (WAN) interfaces simultaneously.

The Agent is built with C++17 and optimized for efficiency, making it suitable for deployment on a wide range of hardware, from embedded gateways and IoT devices to high-performance servers.

## Key Features
*   **Protocol & Application Detection**: Accurately classifies thousands of protocols and applications in real-time, including support for encrypted traffic analysis.
*   **Metadata Extraction**: Extracts rich flow metadata, including network statistics, connection durations, protocol-specific details, and flow risk analysis.
*   **Device Identification**: Analyzes traffic patterns to identify and categorize devices on the network, distinguishing between IoT devices, workstations, mobile devices, and more.
*   **Flexible Data Export**: Classification and flow data are JSON-encoded and can be exported to local files, served over UNIX or TCP sockets, or pushed to remote endpoints via HTTP/S POST requests.
*   **Plugin Architecture**: Supports a modular plugin system that allows for extending functionality, such as custom data sinks, integration with local databases, or specialized analysis modules.
*   **Informatics Integration**: Optionally integrates with the [Netify Informatics](https://www.netify.ai/informatics) cloud platform for advanced machine-learning analysis, historical reporting, event notifications, and long-term storage.
*   **Active Control Support**: On supported platforms, the Agent can be configured to take an active role in network policing, bandwidth shaping, and policy enforcement based on real-time DPI results.

## Download Packages
Supported platforms with installation instructions can be found [here](https://www.netify.ai/get-netify).

Alternatively, binary packages are available for several common distributions.  Visit the [downloads area](https://download.netify.ai/) of the Netify website.

## Download Source
Full [source archives](https://download.netify.ai/source/) are available from the Netify website.

Optionally, the source can be cloned with [git](https://gitlab.com/netify.ai/public/netify-agent.git).  When cloning the source tree, include the `--recursive` option to clone the required sub-modules.

### Build Requirements
Netify requires the following third-party packages:
- libcurl
- libpcap
- zlib
- [Linux] libmnl
- [Linux] libnetfilter-conntrack

Optional:
- google-perftools/gperftools/libtcmalloc (will use bundled version when not available)

### Configuring/Building From Source
Read the appropriate documentation in the `doc/` directory, prefixed with: `BUILD-*`

Generally the process is:
```sh
./autogen.sh
./configure
make
```

## Documentation
Comprehensive user and developer documentation, including configuration guides and API references, can be found at:
[https://www.netify.ai/documentation](https://www.netify.ai/documentation)

The project Wiki is available [here](https://gitlab.com/netify.ai/public/netify-agent/-/wikis/home).

## License
The Netify Agent is dual-licensed under commercial and open source licenses. The commercial license gives you the full rights to create and distribute software on your own terms without any open source license obligations.

The Netify Agent is also available under GPL and LGPL open source licenses.  The open source licensing is ideal for student/academic purposes, hobby projects, internal research projects, or other projects where all open source license obligations can be met.

The Netify Agent includes the following libraries:
- nDPI - LGPL license
- inih -  3-Clause BSD license
- [optional] gperftools - Google license

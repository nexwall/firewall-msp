// Netify Agent
// Copyright (C) 2015-2025 eGloo Incorporated
// <http://www.egloo.ca>
//
// This program is free software: you can redistribute it
// and/or modify it under the terms of the GNU General
// Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be
// useful, but WITHOUT ANY WARRANTY; without even the
// implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE.  See the GNU General Public License
// for more details.
//
// You should have received a copy of the GNU General Public
// License along with this program.  If not, see
// <http://www.gnu.org/licenses/>.

#pragma once

#include <cstdint>
#include <memory>

#include <sys/socket.h>
#include <sys/stat.h>

#include <nd-except.hpp>

class ndSocketHangupException : public std::runtime_error
{
public:
    explicit ndSocketHangupException(const std::string &what_arg)
      : runtime_error(what_arg) { }
};

class ndSocketLocal;
class ndSocketRemote;
class ndSocketClient;
class ndSocketServer;

enum ndSocketType {
    ndSOCKET_TYPE_NULL,
    ndSOCKET_TYPE_CLIENT,
    ndSOCKET_TYPE_SERVER
};

enum ndSocketState {
    ndSOCKET_STATE_INIT,
    ndSOCKET_STATE_CONNECTED,
    ndSOCKET_STATE_ACCEPTED,
    ndSOCKET_STATE_CLOSED,
};

class ndSocket
{
public:
    ndSocket();
    ndSocket(const std::string &node);
    ndSocket(const std::string &node, const std::string &service);
    virtual ~ndSocket();

    void SetBlockingMode(bool enable = false);

    ssize_t Read(uint8_t *buffer, ssize_t length);
    ssize_t Write(const uint8_t *buffer, ssize_t length);

    inline int GetDescriptor(void) { return sd; }

protected:
    friend class ndSocketLocal;
    friend class ndSocketRemote;
    friend class ndSocketClient;
    friend class ndSocketServer;

    void Create(void);

    int sd;
    int family;
    std::unique_ptr<struct sockaddr_storage> sa;
    socklen_t sa_size;
    std::string node;
    std::string service;

    ndSocketType type;
    ndSocketState state;

    uint64_t bytes_in;
    uint64_t bytes_out;
};

class ndSocketLocal
{
protected:
    ndSocketLocal(ndSocket *base, const std::string &node);
    virtual ~ndSocketLocal();

    int IsValid(void);

    ndSocket *base;
    bool valid;
};

class ndSocketRemote
{
protected:
    ndSocketRemote(ndSocket *base,
      const std::string &node, const std::string &service);
    virtual ~ndSocketRemote();

    ndSocket *base;
};

class ndSocketClient
{
protected:
    ndSocketClient(ndSocket *base);
    virtual ~ndSocketClient();

    ndSocket *base;
};

class ndSocketServer
{
public:
    ndSocket *Accept(void);
    virtual ~ndSocketServer();

    inline int GetDescriptor(void) { return base->sd; }

protected:
    ndSocketServer(ndSocket *base);

    ndSocket *base;
};

class ndSocketClientLocal :
  public ndSocket,
  public ndSocketClient,
  protected ndSocketLocal
{
public:
    ndSocketClientLocal(const std::string &node);
    virtual ~ndSocketClientLocal();

protected:
};

class ndSocketServerLocal :
  public ndSocket,
  public ndSocketServer,
  protected ndSocketLocal
{
public:
    ndSocketServerLocal(const std::string &node);
    virtual ~ndSocketServerLocal();

    virtual void SetPermissions(mode_t mode);
protected:
};

class ndSocketClientRemote :
  public ndSocket,
  public ndSocketClient,
  protected ndSocketRemote
{
public:
    ndSocketClientRemote(const std::string &node,
      const std::string &service);
    virtual ~ndSocketClientRemote();

protected:
};

class ndSocketServerRemote :
  public ndSocket,
  public ndSocketServer,
  protected ndSocketRemote
{
public:
    ndSocketServerRemote(const std::string &node,
      const std::string &service);
    virtual ~ndSocketServerRemote();

protected:
};

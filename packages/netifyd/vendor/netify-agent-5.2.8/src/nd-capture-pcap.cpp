// Netify Agent
// Copyright (C) 2015-2024 eGloo Incorporated
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdexcept>
#include <vector>

#include <net/if.h>
#include <sys/ioctl.h>

#include "nd-capture-pcap.hpp"

using namespace std;

ndCapturePcap::ndCapturePcap(int16_t cpu,
  ndInterface::Ptr &iface, const ndDetectionThreads &threads_dpi,
  ndDNSHintCache *dhc, uint8_t private_addr)
  : ndCaptureThread(iface->capture_type, cpu, iface,
      threads_dpi, dhc, private_addr),
    pcap(nullptr), pcap_fd(-1), pkt_header(nullptr),
    pkt_data(nullptr), pcs_last{ 0 } {
    if (ndCT_TYPE(iface->capture_type.flags) == ndCaptureType::PCAP_OFFLINE)
    {
        nd_dprintf("%s: capture file: %s\n", tag.c_str(),
          iface->config_pcap.capture_filename.c_str());
    }

    nd_dprintf("%s: PCAP capture thread created.\n", tag.c_str());
}

ndCapturePcap::~ndCapturePcap() {
    Join();

    if (pcap != nullptr) {
        pcap_close(pcap);
        pcap = nullptr;

        pcap_freecode(&filter);
    }

    nd_dprintf("%s: PCAP capture thread destroyed.\n", tag.c_str());
}

static void pcap_callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    auto queue = reinterpret_cast<vector<ndPacket*>*>(user);
    uint8_t *pd = new uint8_t[h->caplen];
    memcpy(pd, bytes, h->caplen);
    ndFlags<ndPacket::StatusFlags> pkt_status = ndPacket::StatusFlags::OK;
    ndPacket *pkt = new ndPacket(pkt_status, h->len, h->caplen, pd, h->ts);
    queue->push_back(pkt);
}

void *ndCapturePcap::Entry(void) {
    int rc;
    int sd_max = 0;
    struct ifreq ifr;
    struct timeval tv;
    fd_set fds_read;
    bool warnings = true;
    vector<ndPacket*> pkt_queue;
    pkt_queue.reserve(iface->config_pcap.queue_size);

    while (! ShouldTerminate()) {
        if (pcap != nullptr) {
            FD_ZERO(&fds_read);
            //            FD_SET(fd_ipc[0], &fds_read);
            FD_SET(pcap_fd, &fds_read);

            tv.tv_sec = 1;
            tv.tv_usec = 0;
            rc = select(sd_max + 1, &fds_read, nullptr,
              nullptr, &tv);

            if (rc == 0) continue;
            else if (rc == -1) {
                throw ndExceptionSystemError(
                  __PRETTY_FUNCTION__, "select");
            }
#if 0
            if (FD_ISSET(fd_ipc[0], &fds_read)) {
                // TODO: Not used.
                uint32_t ipc_id = RecvIPC();
            }
#endif
            if (! FD_ISSET(pcap_fd, &fds_read)) continue;

            rc = pcap_dispatch(pcap, iface->config_pcap.queue_size, pcap_callback, reinterpret_cast<u_char*>(&pkt_queue));

            if (!pkt_queue.empty()) {
                Lock();
                try {
                    for (auto p : pkt_queue) {
                        if (ProcessPacket(p) != nullptr)
                            delete p;
                    }
                }
                catch (...) {
                    Unlock();
                    throw;
                }
                Unlock();
                pkt_queue.clear();
            }

            if (rc < 0) {
                capture_state = State::OFFLINE;

                if (rc == -1) {
                    nd_printf("%s: %s.\n", tag.c_str(),
                      pcap_geterr(pcap));
                    if (ndCT_TYPE(iface->capture_type.flags) ==
                      ndCaptureType::PCAP_OFFLINE)
                        Terminate();
                    else {
                        pcap_close(pcap);
                        pcap = nullptr;
                        sleep(1);
                    }
                }
                else if (rc == -2) {
                    nd_dprintf(
                      "%s: end of capture file: %s\n", tag.c_str(),
                      iface->config_pcap.capture_filename.c_str());
                    Terminate();
                }
            }
        }
        else if (! ShouldTerminate()) {
            if (ndCT_TYPE(iface->capture_type.flags) !=
                ndCaptureType::PCAP_OFFLINE &&
              (nd_ifreq(tag, SIOCGIFFLAGS, &ifr) == -1 ||
                ! (ifr.ifr_flags & IFF_UP)))
            {
                capture_state = State::OFFLINE;

                if (warnings) {
                    nd_printf(
                      "%s: WARNING: interface not "
                      "available.\n",
                      tag.c_str());
                    warnings = false;
                }
                sleep(1);
                continue;
            }

            warnings = true;

            if ((pcap = OpenCapture()) == nullptr) {
                capture_state = State::OFFLINE;
                sleep(1);
                continue;
            }

            dl_type = pcap_datalink(pcap);
            sd_max = pcap_fd;
            //            sd_max = max(fd_ipc[0], pcap_fd);

            nd_dprintf(
              "%s: PCAP capture started on CPU: %lu\n",
              tag.c_str(), cpu >= 0 ? cpu : 0);
        }
    }

    capture_state = State::OFFLINE;

    nd_dprintf("%s: PCAP capture ended on CPU: %lu\n",
      tag.c_str(), cpu >= 0 ? cpu : 0);

    return nullptr;
}

pcap_t *ndCapturePcap::OpenCapture(void) {
    pcap_t *pcap_new = nullptr;

    memset(pcap_errbuf, 0, PCAP_ERRBUF_SIZE);

    if (ndCT_TYPE(iface->capture_type.flags) == ndCaptureType::PCAP_OFFLINE)
    {
        if ((pcap_new = pcap_open_offline(
               iface->config_pcap.capture_filename.c_str(),
               pcap_errbuf)) != nullptr)
        {
            tv_epoch = time(nullptr);
            nd_dprintf(
              "%s: reading from capture file: %s: v%d.%d\n",
              tag.c_str(),
              iface->config_pcap.capture_filename.c_str(),
              pcap_major_version(pcap_new),
              pcap_minor_version(pcap_new));
        }
    }
    else {
        pcap_new = pcap_create(tag.c_str(), pcap_errbuf);
        if (pcap_new != nullptr) {
            pcap_set_snaplen(pcap_new, ndGC.max_capture_length);
            pcap_set_promisc(pcap_new, 1);
            pcap_set_timeout(pcap_new, ndGC.capture_read_timeout);
            pcap_set_buffer_size(pcap_new, iface->config_pcap.buffer_size);
            pcap_set_immediate_mode(pcap_new, 0);

            int status = pcap_activate(pcap_new);
            if (status < 0) {
                nd_printf("%s: pcap_activate: %s\n", tag.c_str(), pcap_geterr(pcap_new));
                pcap_close(pcap_new);
                pcap_new = nullptr;
            } else if (status > 0) {
                nd_dprintf("%s: pcap_activate warning: %s\n", tag.c_str(), pcap_geterr(pcap_new));
            }
        }

#if 0
        if (pcap_new != nullptr) {
            bool adapter = false;
            int *pcap_tstamp_types, count;
            if ((count = pcap_list_tstamp_types(pcap_new, &pcap_tstamp_types)) > 0) {
                for (int i = 0; i < count; i++) {
                    nd_dprintf("%s: tstamp_type: %s\n", tag.c_str(),
                        pcap_tstamp_type_val_to_name(pcap_tstamp_types[i]));
                    if (pcap_tstamp_types[i] == PCAP_TSTAMP_ADAPTER)
                        adapter = true;
                }

                pcap_free_tstamp_types(pcap_tstamp_types);

                //if (adapter) {
                //    if (pcap_set_tstamp_type(pcap_new, PCAP_TSTAMP_ADAPTER) != 0) {
                //        nd_printf("%s: Failed to set timestamp type: %s\n", tag.c_str(),
                //            pcap_geterr(pcap_new));
                //    }
                //}
            }
        }
#endif
    }

    if (pcap_new == nullptr)
        nd_printf("%s: pcap_open: %s\n", tag.c_str(), pcap_errbuf);
    else {
        capture_state = State::ONLINE;

        unsigned ifindex = if_nametoindex(tag.c_str());
        if (ifindex == 0) {
            nd_dprintf("%s: if_nametoindex: %s\n", tag.c_str(), strerror(errno));
            iface->ifindex = -1;
        }
        else iface->ifindex = (int)ifindex;

        if (ndCT_TYPE(iface->capture_type.flags) !=
          ndCaptureType::PCAP_OFFLINE)
        {
            if (pcap_setnonblock(pcap_new, 1, pcap_errbuf) == PCAP_ERROR)
                nd_printf("%s: pcap_setnonblock: %s\n",
                  tag.c_str(), pcap_errbuf);
        }

        if ((pcap_fd = pcap_get_selectable_fd(pcap_new)) < 0)
            nd_dprintf("%s: pcap_get_selectable_fd: -1\n",
              tag.c_str());

        auto i = ndGC.interface_filters.find(tag);

        if (i != ndGC.interface_filters.end()) {
            try {
                CompileFilter(i->second, filter, pcap_new);
            } catch (exception &e) {
                nd_printf("%s: pcap_compile: %s\n",
                  tag.c_str(), pcap_geterr(pcap_new));
                nd_dprintf("%s: expression: %s\n",
                  tag.c_str(), i->second.c_str());
                pcap_close(pcap_new);
                return nullptr;
            }

            if (pcap_setfilter(pcap_new, &filter) < 0) {
                nd_printf("%s: pcap_setfilter: %s\n",
                  tag.c_str(), pcap_geterr(pcap_new));
                pcap_close(pcap_new);
                return nullptr;
            }
        }
    }

    return pcap_new;
}

void ndCapturePcap::GetCaptureStats(ndPacketStats &stats) {
    if (pcap != nullptr &&
      ndCT_TYPE(iface->capture_type.flags) != ndCaptureType::PCAP_OFFLINE)
    {
        struct pcap_stat pcs;
        memset(&pcs, 0, sizeof(struct pcap_stat));

        if (pcap_stats(pcap, &pcs) == 0) {
            uint64_t dropped = pcs.ps_drop + pcs.ps_ifdrop;

            if (pcs_last.ps_drop <= pcs.ps_drop)
                dropped -= pcs_last.ps_drop;
            if (pcs_last.ps_ifdrop <= pcs.ps_ifdrop)
                dropped -= pcs_last.ps_ifdrop;

            this->stats.pkt.capture_dropped = dropped;

            memcpy(&pcs_last, &pcs, sizeof(struct pcap_stat));
        }
    }

    ndCaptureThread::GetCaptureStats(stats);
}

#pragma once

#include <string>
#include <fstream>
#include <iostream>
#include <cmath>

struct pcap_hdr_s 
{
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t  thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets, in octets */
    uint32_t network;
    void getHdr(std::ifstream& in);

    private:

    uint32_t readU32(std::ifstream& in);

    uint16_t readU16(std::ifstream& in);
};

struct pcap_rec_hdr_s {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
    void getRecHdr (std::ifstream& in);

    private:

    uint32_t readU32(std::ifstream& in);
};

class PCAPReader {
    const std::string fileName;

    uint32_t reverse(uint32_t num) const;

public:
    explicit PCAPReader(const std::string &fileName);

    // Количество пакетов в файле
    uint64_t packetsCount() const;

    // Общий объём полезной нагрузки (без учёта заголовков)
    uint64_t payloadSize() const;
};

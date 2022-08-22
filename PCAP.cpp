#include "PCAP.h"

void pcap_hdr_s::getHdr(std::ifstream& in)
{
    pcap_hdr_s var;
    magic_number = readU32(in);
    version_major = readU16(in);
    version_minor = readU16(in);
    thiszone = readU32(in);
    sigfigs = readU32(in);
    snaplen = readU32(in);
    network = readU32(in);
}

uint32_t pcap_hdr_s::readU32(std::ifstream& in)
{
    unsigned char a;
    uint32_t result{0};
    for (int i{0}; i<4; ++i)
    {
        result*=256;
        a = in.get();
        result+=a;
    }
    return result;
}

uint16_t pcap_hdr_s::readU16(std::ifstream& in)
{
    unsigned char a;
    uint32_t result{0};
    for (int i{0}; i<2; ++i)
    {
        result*=256;
        a = in.get();
        result+=a;
    }
    return result;
}

void pcap_rec_hdr_s::getRecHdr(std::ifstream& in)
{
    ts_sec = readU32(in);
    ts_usec= readU32(in);
    incl_len = readU32(in);
    orig_len = readU32(in);
}

uint32_t pcap_rec_hdr_s::readU32(std::ifstream& in)
{
    unsigned char a;
    uint32_t result{0};
    for (int i{0}; i<4; ++i)
    {
        result*=256;
        a = in.get();
        result+=a;
    }
    return result;
}

PCAPReader::PCAPReader(const std::string &fileName): fileName(fileName)
{}


uint32_t PCAPReader::reverse(uint32_t num) const
{
    uint32_t result{0};
    uint64_t i{1};
    uint32_t pow3_256=256*256*256;
    for (i; i<=pow3_256; i*=256)
    {
        result += (num%256)*pow3_256/i;
        num /=256;
    }
    return result;
}

uint64_t PCAPReader::packetsCount() const
{
    uint64_t result {0};
    std::ifstream file(fileName, std::ios::in | std::ios::binary);
    pcap_hdr_s hdr;
    pcap_rec_hdr_s rec_hdr;
    char buff_ignore;
    bool reversing = false;
    if (!file.is_open()) {
        return -1;
    } else {
        hdr.getHdr(file);
        if (hdr.magic_number==0xd4c3b2a1)
            reversing = true;
        buff_ignore = file.get();
        while (!file.eof())
        {
            file.unget();
            rec_hdr.getRecHdr(file);
            if (reversing)
                rec_hdr.incl_len=reverse(rec_hdr.incl_len);
            uint32_t num_bytes = rec_hdr.incl_len;
            result++;
            file.ignore(num_bytes);
            buff_ignore = file.get();
        }
        return result;
    }
}

uint64_t PCAPReader::payloadSize() const
{
    uint64_t result {0};
    std::ifstream file(fileName, std::ios::in | std::ios::binary);
    pcap_hdr_s hdr;
    pcap_rec_hdr_s rec_hdr;
    char buff_ignore;
    bool reversing = false;
    if (!file.is_open()) {
        return -1;
    } else {
        hdr.getHdr(file);
        if (hdr.magic_number==0xd4c3b2a1)
            reversing = true;
        buff_ignore = file.get();
        while (!file.eof())
        {
            file.unget();
            rec_hdr.getRecHdr(file);
            if (reversing)
                rec_hdr.incl_len=reverse(rec_hdr.incl_len);
            uint32_t num_bytes = rec_hdr.incl_len;
            result+=num_bytes;
            file.ignore(num_bytes);
            buff_ignore = file.get();
        }
        return result;
    }
}
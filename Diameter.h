#ifndef DIAMETERMSG_H
#define DIAMETERMSG_H

#include <cstdint> 
#include <cstddef> 
#include "AVP.h" 

uint32_t read24(const uint8_t* d); 
uint32_t read32(const uint8_t* d);

bool processCER(const DiameterMsg& cer); 

class DiameterMsg{
    private: 
        uint8_t version_; 
        uint32_t messageLen_; 
        uint8_t flags_; 
        uint32_t commandCode_;
        uint32_t applicationId_; 
        uint32_t hopByHop_; 
        uint32_t endToEnd_;
        AVP avpData_[50]; 
        int avpCount_;
    public: 
        int decoder(const uint8_t* data, size_t dataLen); 
        void printAll() const; 
        const AVP* findAVP(uint32_t code) const;

        uint32_t getCommantCode() const{ return commandCode_;}

        bool isRequest() const { return (flags_ & 0x80); }

        uint32_t getAppId() const { return applicationId_; }
        uint32_t getHopByHop() const { return hopByHop_; }
        uint32_t getEndToEnd() const { return endToEnd_; }
        uint8_t getFlags() const { return flags_; }
};
#endif 

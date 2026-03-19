#ifndef AVP_H 
#define AVP_H
#include <cstdint> 
class DiameterMsg; 
class AVP{
    private: 
        uint32_t code_; 
        uint8_t flags_; 
        uint32_t length_; 
        uint32_t vendorId_; 
        const uint8_t* data_; 
        uint32_t dataLen_; 

        friend class DiameterMsg;
    bool hasVendor() const { return (flags_ & 0x80);}
    bool isMandatory() const { return (flags_ & 0x40);}
    bool isProtected() const  { return (flags_ & 0x20);}

}; 
#endif

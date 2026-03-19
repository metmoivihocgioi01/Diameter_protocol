#include "DiameterMsg.h" 

#include <iostream> 
#include <cctype> 
#include <vector>
#include <cstring>

#include <arpa/inet.h>


using namespace std;

uint32_t read24(const uint8_t* d){
    return (uint32_t(d[0]) << 16) | (uint32_t(d[1]) << 8) | uint32_t(d[2]);
}
uint32_t read32(const uint8_t* d){
    return (uint32_t(d[0]) << 24) | (uint32_t(d[1]) << 16) | (uint32_t(d[2]) << 8) | uint32_t(d[3]);
} 

void write24(uint8_t* d, uint32_t val){
    d[0] = (val >> 16) & 0xFF;
    d[1] = (val >> 8) & 0xFF;
    d[2] = val & 0xFF;
}

void write32(uint8_t* d, uint32_t val){
    d[0] = (val >> 24) & 0xFF;
    d[1] = (val >> 16) & 0xFF;
    d[2] = (val >> 8) & 0xFF;
    d[3] = val & 0xFF;
}

std::vector<uint8_t> encodeCEA(const DiameterMsg& msg){
    std::vector<uint8_t> buffer(20);

    buffer[0] = 1;
    buffer[4] = msg.getFlags();

    write24(&buffer[5], msg.getCommantCode());
    write32(&buffer[8], msg.getAppId());
    write32(&buffer[12], msg.getHopByHop());
    write32(&buffer[16], msg.getEndToEnd());

    // AVP sẽ thêm sau (CEA đơn giản)

    write24(&buffer[1], buffer.size());

    return buffer;
}



int DiameterMsg::decoder(const uint8_t* data, size_t dataLen){
    if(dataLen < 20)
        return -1;

    version_ = data[0];
    messageLen_ = read24(&data[1]);
    flags_ = data[4];
    commandCode_ = read24(&data[5]);
    applicationId_ = read32(&data[8]);
    hopByHop_ = read32(&data[12]);
    endToEnd_ = read32(&data[16]);

    if(messageLen_ > dataLen)
        return -1;

    size_t pos = 20;
    avpCount_ = 0;

    while(pos < messageLen_ && avpCount_ < 50){

        if(pos + 8 > messageLen_)
            return -1;

        AVP& avp = avpData_[avpCount_];

        avp.code_ = read32(&data[pos]);
        avp.flags_ = data[pos+4];
        avp.length_ = read24(&data[pos+5]);

        size_t headerSize = 8;

        if(avp.hasVendor()){
            avp.vendorId_ = read32(&data[pos+8]);
            headerSize = 12;
        }else{
            avp.vendorId_ = 0;
        }

        avp.data_ = &data[pos + headerSize];
        avp.dataLen_ = avp.length_ - headerSize;

        avpCount_++;

        size_t paddedLen = (avp.length_ + 3) & ~3;
        pos += paddedLen;
    }

    return 0;
}

const AVP* DiameterMsg::findAVP(uint32_t code) const{
    for (int i = 0; i < avpCount_; i++){
        if(avpData_[i].code_ == code){
            return &avpData_[i];
        }
    }
    return nullptr;
}

bool processCER(const DiameterMsg& cer){

    if(cer.getCommantCode() != 257 || !cer.isRequest()){
        cout << "[ERROR] Not CER (Request)" << endl;
        return false;
    }

    const AVP* originHost = cer.findAVP(264);
    const AVP* originRealm = cer.findAVP(296);
    const AVP* hostIP = cer.findAVP(257);
    const AVP* vendorId = cer.findAVP(266);
    const AVP* productName = cer.findAVP(269);

    if (!originHost || !originRealm || !hostIP || !vendorId || !productName){
        cout << "[ERROR] CER missing mandatory AVP" << endl;
        return false;
    }

    cout << "[INFO] CER validated successfully" << endl;
    return true;
}

void DiameterMsg::printAll() const{

    cout << "========== DIAMETER HEADER ==========" << endl;
    cout << "Version: " << int(version_) << endl;
    cout << "Message Length: " << messageLen_ << endl;
    cout << "Command Code: " << commandCode_ << endl;
    cout << "Application ID: " << applicationId_ << endl;
    cout << "Hop-by-Hop: 0x" << hex << hopByHop_ << endl;
    cout << "End-to-End: 0x" << hex << endToEnd_ << dec << endl;
    cout << "AVP Count: " << avpCount_ << endl << endl;

    cout << "========== AVP LIST ==========" << endl;

    for(int i = 0; i < avpCount_; i++){

        const AVP& avp = avpData_[i];

        cout << "---- AVP# " << i+1 << " ----" << endl;
        cout << "Code: " << avp.code_ << endl;
        cout << "Flags: 0x" << hex << int(avp.flags_) << dec << endl;
        cout << "V-bit: " << avp.hasVendor() << endl;
        cout << "M-bit: " << avp.isMandatory() << endl;
        cout << "P-bit: " << avp.isProtected() << endl;
        cout << "Length: " << avp.length_ << endl;

        if(avp.hasVendor())
            cout << "Vendor-ID: " << avp.vendorId_ << endl;

        cout << "Data length: " << avp.dataLen_ << endl;
        cout << "Data (ASCII): ";

        for(uint32_t j = 0; j < avp.dataLen_; j++){
            if(isprint(avp.data_[j]))
                cout << char(avp.data_[j]);
        }

        cout << endl << endl;
    }
}

std::vector<uint8_t> buildCEA(const DiameterMsg& cer){
    std::vector<uint8_t> buffer(20);

    buffer[0] = 1;

    // Flags = 0 (Answer)
    buffer[4] = 0x00;

    write24(&buffer[5], 257);
    write32(&buffer[8], cer.getAppId());
    write32(&buffer[12], cer.getHopByHop());
    write32(&buffer[16], cer.getEndToEnd());

    // ==== AVP Result-Code (268) ====
    uint8_t avp[12];

    write32(&avp[0], 268);      // code
    avp[4] = 0x40;              // mandatory
    write24(&avp[5], 12);       // length

    uint32_t result = htonl(2001);
    memcpy(&avp[8], &result, 4);

    buffer.insert(buffer.end(), avp, avp+12);

    // update length
    write24(&buffer[1], buffer.size());

    return buffer;
}


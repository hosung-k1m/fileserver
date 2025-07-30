#include "../include/byte_stream.h"

// byte = 8 bits
void ByteStream::writeByte(uint8_t val) {
    buffer_.push_back(val);
}

// write a 32 bit int split into four 1 byte chunks in big endian
void ByteStream::writeUint32(uint32_t val) {
    for (int i=3; i >= 0; i--) {
        buffer_.push_back((val >> (8 * i)) & 0xFF);
    }
}

// size string, then chars in buffer --> encode
void ByteStream::writeString(const std::string& val) {
    writeUint32(val.size());
    buffer_.insert(buffer_.end(), val.begin(), val.end());
}

void ByteStream::writeNameList(const std::vector<std::string>& names) {
    std::string combined;
    for (size_t i=0; i < names.size(); i++) {
        combined += names[i];
        if (i!= names.size() -1) {
            combined += ",";
        }
    }

    writeString(combined);
}

void ByteStream::writeRaw(const std::vector<uint8_t>& val) {
    buffer_.insert(buffer_.end(), val.begin(), val.end());
}

const std::vector<uint8_t>& ByteStream::data() const {
    return buffer_;
}

void ByteStream::writeMpint(const std::vector<uint8_t>& val) {
    std::vector<uint8_t> buf = val;
    
    // validate unsigned value
    if (!buf.empty() && (buf[0] & 0x80)) {
        buf.insert(buf.begin(), 0x00);
    }
    writeUint32(buf.size());
    buffer_.insert(buffer_.end(), buf.begin(), buf.end());
}
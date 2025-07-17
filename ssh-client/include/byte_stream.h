#pragma once
#include <vector>
#include <string>
#include <cstdint>

class BysteStream {
    public:
        void writeByte(uint8_t val);
        void writeUint32(uint32_t val);
        void writeString(const std::string& val);
        void writeNameList(const std::vector<std::string>& names);

    const std::vector<uint8_t>& data() const;
    
    private:
        std::vector<uint8_t> buffer_;
};
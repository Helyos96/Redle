/*
 * This file is part of the TrinityCore Project. See AUTHORS file for Copyright information
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "ByteBuffer.h"
#include "StringFormat.h"
#include "utf8.h"
#include <sstream>
#include <cmath>
#include <ctime>

ByteBufferPositionException::ByteBufferPositionException(size_t pos, size_t size, size_t valueSize)
{
    std::ostringstream ss;

    ss << "Attempted to get value with size: "
       << valueSize << " in ByteBuffer (pos: " << pos << " size: " << size
       << ")";

    message().assign(ss.str());
}

ByteBufferInvalidValueException::ByteBufferInvalidValueException(char const* type, char const* value)
{
    message().assign(Trinity::StringFormat("Invalid {} value ({}) found in ByteBuffer", type, value));
}

ByteBuffer& ByteBuffer::operator>>(float& value)
{
    value = read<float>();
    if (!std::isfinite(value))
        throw ByteBufferInvalidValueException("float", "infinity");
    return *this;
}

ByteBuffer& ByteBuffer::operator>>(double& value)
{
    value = read<double>();
    if (!std::isfinite(value))
        throw ByteBufferInvalidValueException("double", "infinity");
    return *this;
}

std::string ByteBuffer::ReadCString(bool requireValidUtf8 /*= true*/)
{
    std::string value;
    while (rpos() < size())                         // prevent crash at wrong string format in packet
    {
        char c = read<char>();
        if (c == 0)
            break;
        value += c;
    }
    if (requireValidUtf8 && !utf8::is_valid(value.begin(), value.end()))
        throw ByteBufferInvalidValueException("string", value.c_str());
    return value;
}

std::string ByteBuffer::ReadString(uint32_t length, bool requireValidUtf8 /*= true*/)
{
    if (_rpos + length > size())
        throw ByteBufferPositionException(_rpos, length, size());

    ResetBitPos();
    if (!length)
        return std::string();

    std::string value(reinterpret_cast<char const*>(&_storage[_rpos]), length);
    _rpos += length;
    if (requireValidUtf8 && !utf8::is_valid(value.begin(), value.end()))
        throw ByteBufferInvalidValueException("string", value.c_str());
    return value;
}

uint32_t ByteBuffer::ReadPackedTime()
{
    uint32_t packedDate = read<uint32_t>();
    tm lt = tm();

    lt.tm_min = packedDate & 0x3F;
    lt.tm_hour = (packedDate >> 6) & 0x1F;
    //lt.tm_wday = (packedDate >> 11) & 7;
    lt.tm_mday = ((packedDate >> 14) & 0x3F) + 1;
    lt.tm_mon = (packedDate >> 20) & 0xF;
    lt.tm_year = ((packedDate >> 24) & 0x1F) + 100;

    return uint32_t(mktime(&lt));
}

void ByteBuffer::append(uint8_t const* src, size_t cnt)
{
    /*ASSERT(src, "Attempted to put a NULL-pointer in ByteBuffer (pos: " SZFMTD " size: " SZFMTD ")", _wpos, size());
    ASSERT(cnt, "Attempted to put a zero-sized value in ByteBuffer (pos: " SZFMTD " size: " SZFMTD ")", _wpos, size());
    ASSERT(size() < 10000000);*/

    FlushBits();

    size_t const newSize = _wpos + cnt;
    if (_storage.capacity() < newSize) // custom memory allocation rules
    {
        if (newSize < 100)
            _storage.reserve(300);
        else if (newSize < 750)
            _storage.reserve(2500);
        else if (newSize < 6000)
            _storage.reserve(10000);
        else
            _storage.reserve(400000);
    }

    if (_storage.size() < newSize)
        _storage.resize(newSize);
    std::memcpy(&_storage[_wpos], src, cnt);
    _wpos = newSize;
}

/*void ByteBuffer::AppendPackedTime(time_t time)
{
    tm lt;
    localtime_r(&time, &lt);
    append<uint32_t>((lt.tm_year - 100) << 24 | lt.tm_mon << 20 | (lt.tm_mday - 1) << 14 | lt.tm_wday << 11 | lt.tm_hour << 6 | lt.tm_min);
}*/

void ByteBuffer::put(size_t pos, uint8_t const* src, size_t cnt)
{
    /*ASSERT(pos + cnt <= size(), "Attempted to put value with size: " SZFMTD " in ByteBuffer (pos: " SZFMTD " size: " SZFMTD ")", cnt, pos, size());
    ASSERT(src, "Attempted to put a NULL-pointer in ByteBuffer (pos: " SZFMTD " size: " SZFMTD ")", pos, size());
    ASSERT(cnt, "Attempted to put a zero-sized value in ByteBuffer (pos: " SZFMTD " size: " SZFMTD ")", pos, size());*/

    std::memcpy(&_storage[pos], src, cnt);
}

void ByteBuffer::PutBits(std::size_t pos, std::size_t value, uint32_t bitCount)
{
    /*ASSERT(pos + bitCount <= size() * 8, "Attempted to put %u bits in ByteBuffer (bitpos: " SZFMTD " size: " SZFMTD ")", bitCount, pos, size());
    ASSERT(bitCount, "Attempted to put a zero bits in ByteBuffer");*/

    for (uint32_t i = 0; i < bitCount; ++i)
    {
        std::size_t wp = (pos + i) / 8;
        std::size_t bit = (pos + i) % 8;
        if ((value >> (bitCount - i - 1)) & 1)
            _storage[wp] |= 1 << (7 - bit);
        else
            _storage[wp] &= ~(1 << (7 - bit));
    }
}

void ByteBuffer::print_storage() const
{
    std::ostringstream o;
    o << "STORAGE_SIZE: " << size();
    for (uint32_t i = 0; i < size(); ++i)
        o << read<uint8_t>(i) << " - ";
    o << " ";
}

void ByteBuffer::textlike() const
{
    std::ostringstream o;
    o << "STORAGE_SIZE: " << size();
    for (uint32_t i = 0; i < size(); ++i)
    {
        char buf[2];
        snprintf(buf, 2, "%c", read<uint8_t>(i));
        o << buf;
    }
    o << " ";
}

void ByteBuffer::hexlike() const
{
    uint32_t j = 1, k = 1;

    std::ostringstream o;
    o << "STORAGE_SIZE: " << size();

    for (uint32_t i = 0; i < size(); ++i)
    {
        char buf[4];
        snprintf(buf, 4, "%2X", read<uint8_t>(i));
        if ((i == (j * 8)) && ((i != (k * 16))))
        {
            o << "| ";
            ++j;
        }
        else if (i == (k * 16))
        {
            o << "\n";
            ++k;
            ++j;
        }

        o << buf;
    }
    o << " ";
}

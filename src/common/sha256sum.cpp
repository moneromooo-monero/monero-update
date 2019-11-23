// Copyright (c) 2017-2019, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <openssl/sha.h>
#include "file_io_utils.h"
#include "sha256sum.h"

namespace tools
{
  bool sha256sum(const uint8_t *data, size_t len, uint8_t hash[32])
  {
    SHA256_CTX ctx;
    if (!SHA256_Init(&ctx))
      return false;
    if (!SHA256_Update(&ctx, data, len))
      return false;
    if (!SHA256_Final((unsigned char*)hash, &ctx))
      return false;
    return true;
  }

  bool sha256sum(const std::string &filename, uint8_t hash[32])
  {
    if (!epee::file_io_utils::is_file_exist(filename))
      return false;
    std::ifstream f;
    f.exceptions(std::ifstream::failbit | std::ifstream::badbit);
    f.open(filename, std::ios_base::binary | std::ios_base::in | std::ios::ate);
    if (!f)
      return false;
    std::ifstream::pos_type file_size = f.tellg();
    SHA256_CTX ctx;
    if (!SHA256_Init(&ctx))
      return false;
    size_t size_left = file_size;
    f.seekg(0, std::ios::beg);
    while (size_left)
    {
      char buf[4096];
      std::ifstream::pos_type read_size = size_left > sizeof(buf) ? sizeof(buf) : size_left;
      f.read(buf, read_size);
      if (!f || !f.good())
        return false;
      if (!SHA256_Update(&ctx, buf, read_size))
        return false;
      size_left -= read_size;
    }
    f.close();
    if (!SHA256_Final((unsigned char*)hash, &ctx))
      return false;
    return true;
  }
}

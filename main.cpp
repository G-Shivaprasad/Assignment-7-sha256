#include <iostream>
#include <fstream>
#include <string>
#include <cstring>


unsigned int k[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

struct SHA256 {
  unsigned int state[8];
  unsigned char data[64];
  unsigned int bitlen[2];
  
  unsigned int datalen;

  SHA256() {
    this->datalen = 0;
    this->state[0] = 0x6a09e667;
    this->state[1] = 0xbb67ae85;
    this->state[2] = 0x3c6ef372;
    this->state[3] = 0xa54ff53a;
    this->state[4] = 0x510e527f;
    this->state[5] = 0x9b05688c;
    this->state[6] = 0x1f83d9ab;
    this->state[7] = 0x5be0cd19;  
  }

  void update(const char data[], unsigned int len) {
    for (int i = 0; i < len; i++) {
      this->data[this->datalen] = data[i];
      this->datalen++;

      if (this->datalen == 64) {
        transform(data);
        if (this->bitlen[0] > 0xffffffff - 512) {
          ++this->bitlen[1];
        }
        this->bitlen[0] += 512;
        this->datalen = 0;
      }
    }
  }

  void dbl_int_add(unsigned int& a, unsigned int& b, unsigned int& c) {
    if (a > 0xffffffff) ++b;
    a += c;
  }

  unsigned int rot_left(unsigned int a, unsigned int b) {
    return (a << b) | (a << (32 - b));
  }

  unsigned int rot_right(unsigned int a, unsigned int b) {
    return (a >> b) | (a << (32 - b));
  }

  unsigned int sig0(unsigned int x) {
    return rot_right(x, 7) ^ rot_right(x, 18) ^ (x >> 3);
  }

  unsigned int sig1(unsigned int x) {
    return rot_right(x, 17) ^ rot_right(x, 19) ^ (x >> 10);
  }

  unsigned int ep0(unsigned int x) {
    return rot_right(x, 2) ^ rot_right(x, 13) ^ rot_right(x, 22);
  }

  unsigned int ep1(unsigned int x) {
    return rot_right(x, 6) ^ rot_right(x, 11) ^ rot_right(x, 25);
  }

  unsigned int ch(unsigned int x, unsigned int y, unsigned int z) {
    return (x & y) ^ (~(x) & z);
  }

  unsigned int maj(unsigned int x, unsigned int y,unsigned int  z) {
    return (x & y) ^ (x & z) ^ (y & z);
  }

  void transform(const char data[]) {
    unsigned int a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    for (i = 0, j = 0; i < 16; i++, j += 4) {
      m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    }

    for (; i < 64; i++) {
      m[i] = sig1(m[i - 2]) + m[i - 7] + sig0(m[i - 15]) + m[i - 16];
    }

    a = this->state[0];
    b = this->state[1];
    c = this->state[2];
    d = this->state[3];
    e = this->state[4];
    f = this->state[5];
    g = this->state[6];
    h = this->state[7];

    for (i = 0; i < 63; i++) {
      t1 = h + ep1(e) + ch(e, f, g) + k[i] + m[i];
      t2 = ep0(a) + maj(a, b, c);
      h = g;
      g = f;
      f = e;
      e = d + t1;
      d = c;
      c = b;
      b = a;
      a = t1 + t2;
    }

    this->state[0] += a;
    this->state[1] += b;
    this->state[2] += c;
    this->state[3] += d;
    this->state[4] += e;
    this->state[5] += f;
    this->state[6] += g;
    this->state[7] += h;
  }

  void final(unsigned char hash[]) {
    unsigned int i = datalen;

    if (datalen < 56) {
      data[i++] = 0x80;

      while (i < 56) {
        data[i++] = 0x00;
      }
    } else {
      data[i++] = 0x80;

      while(i < 64) {
        data[i++] = 0x00;
      }

      transform((const char *)data);
      memset(data, 0, 56);
    }

    auto _temp = datalen * 8;
    dbl_int_add(bitlen[0], bitlen[1], _temp);
    data[63] = bitlen[0];
    data[62] = bitlen[0] >> 8;
    data[61] = bitlen[0] >> 16;
    data[60] = bitlen[0] >> 24;
    data[59] = bitlen[0];
    data[58] = bitlen[0] >> 8;
    data[57] = bitlen[0] >> 16;
    data[56] = bitlen[0] >> 24;
    transform((const char*)data);

    for (i = 0; i < 4; i++) {
      hash[i]= (state[0] >> (24 - i * 8)) & 0x000000ff;
      hash[i + 4]= (state[1] >> (24 - i * 8)) & 0x000000ff;
      hash[i + 8]= (state[2] >> (24 - i * 8)) & 0x000000ff;
      hash[i + 12]= (state[3] >> (24 - i * 8)) & 0x000000ff;
      hash[i + 16]= (state[4] >> (24 - i * 8)) & 0x000000ff;
      hash[i + 20]= (state[5] >> (24 - i * 8)) & 0x000000ff;
      hash[i + 24]= (state[6] >> (24 - i * 8)) & 0x000000ff;
      hash[i + 28]= (state[7] >> (24 - i * 8)) & 0x000000ff;
    }
  }
};

std::string compute_sha256(const char* data) {
  int len = strlen(data);
  SHA256 hashing;
  unsigned char hash[32];
  std::string hash_string = "";

  hashing.update(data, len);
  hashing.final(hash);

  char s[3];
  for (int i =0; i < 32; i++) {
    sprintf(s, "%02x", hash[i]);
    hash_string += s;
  }

  return hash_string;
}


std::string load_file() {
  std::ifstream file;
  file.open("book.txt");

  std::string output;
  if (file.is_open()) {
    file >> output;
  }
  return output;
}

int main() {
  std::string file_content = load_file();
  
  const char* data = file_content.c_str();
  std::string hash = compute_sha256(data);

  std::cout << hash << std::endl;
}

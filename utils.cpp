#include <cstdlib>
#include <cstdio>
#include <cstring>

#include "utils.h"

void printPacket(const uint8_t *buffer, uint32_t size)
{
#define ppMIN(a, b)       ((a) < (b) ? (a) : (b))
	char* stringbuffer = new char[size+2048]; // 256 bytes for the message around it.
	memset(stringbuffer, 0, (size + 2048 )* sizeof(char));

	unsigned int i;
	sprintf(stringbuffer + strlen(stringbuffer), "Printing packet with size %u\n", size);
   
	for(i = 0; i < size; ++i) {
		if(i != 0&& i%16 == 0) {
			for(unsigned int j = i-16; j < i; ++j) {
				if(buffer[j] >= 32 && buffer[j] <= 126)
					sprintf(stringbuffer + strlen(stringbuffer), "%c", buffer[j]);
				else
					sprintf(stringbuffer + strlen(stringbuffer), ".");
			}

			sprintf(stringbuffer + strlen(stringbuffer), "\n");
		}

		if(i%16 == 0) {
			sprintf(stringbuffer + strlen(stringbuffer), "%04d-%04d ", i, ppMIN(i + 15, size - 1));
		}

		sprintf(stringbuffer + strlen(stringbuffer), "%02X ", buffer[i]);
	}
   
	for(i = ((16-i%16)%16); i > 0; --i)
		sprintf(stringbuffer + strlen(stringbuffer), "   ");
   
	for(i = size- (size%16 == 0 ? 16 : size%16); i < size; ++i) {
		if(buffer[i] >= 32 && buffer[i] <= 126)
			sprintf(stringbuffer + strlen(stringbuffer), "%c", buffer[i]);
		else
			sprintf(stringbuffer + strlen(stringbuffer), ".");
	}
   
	sprintf(stringbuffer + strlen(stringbuffer), "\r\n");

	printf("%s", stringbuffer);
	delete[] stringbuffer;
}
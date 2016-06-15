#include "mybuffer.h"

#include <sstream>

/**
 * 把value转换成一个16进制的字符。
 * \param value value属于[0,15]
 */
 char hexchar(uint8_t value){
	static char str[]="0123456789abcdef";
	if(value>=16) return '*';
	return str[value];
}

 std::string hexUINT8(uint8_t value){
	 char buff[3];
	 buff[0]=hexchar(value >> 4);//高四位
	 buff[1]=hexchar(value & 0xF);//低四位
	 buff[2]='\0';
	 return buff;
 }

 std::string GetIPFromUINT8(const uint8_t* buff){
	 buff+=1;
	 std::ostringstream oss;
	 oss<<(int)(*buff)<<"."<<(int)(*(buff+1))<<"."<<(int)(*(buff+2))<<"."<<(int)(*(buff+3))<<":";
	 uint16_t ret=((*(buff+4))<<8)+(*(buff+5));
	 oss<<(int)ret;
	 return oss.str();
 }

/**
 * \param length 可以小于等于0。此时什么都不输出
 */
 std::string hexBuffer(const uint8_t* buff,int length){
	std::ostringstream oss;
	oss<<std::hex<<std::uppercase;
	for(int i=0;i!=length;++i)
		oss<<hexchar(buff[i]>>4)<<hexchar(buff[i]&0xF);
	return oss.str();
}


size_t  write7bitInt(uint64_t value, void *dest){
	uint64_t v2; 
	size_t v3;
	signed int v4;
	char source[12]; 

	v2 = value;
	v3 = 0;
	v4 = 10;
	do
	{
		--v4;

		if ( v3 )
			source[v4] = v2 & 0x7F | 0x80;
		else 
			source[v4] = v2 & 0x7F;
		v2 >>= 7;		
		++v3;
	}
	while ( v2 && v3 < 10 );
	if ( dest )
		memmove(dest, &source[v4], v3);
	return v3;
}

// 往outVar中写入读到的值。return读了多少个字节
int  readVarLength(const uint8_t *buffer, uint32_t *outVar, const uint8_t *bufferEnd)
{
	const uint8_t *v3; 
	int result; 
	uint32_t value;
	v3 = bufferEnd;
	if ( bufferEnd
		&& bufferEnd >= buffer
		&& (result = readVarInt32(buffer, &value, bufferEnd)) != 0
		&& value>=0
		&& (int32_t)value <= v3-result - buffer )// 很重要的安全检查！
	{
		if ( outVar )
			*outVar = value;
	}
	else
	{
		result = 0;
	}
	return result;
}


int readVarInt32(const uint8_t *a1, uint32_t* a2, const uint8_t *a3)
{
	int result;
	uint64_t v4; 

	result = readVarInt64(a1, &v4, a3);
	if ( result && a2 )
	{
		if ( v4 <= 0xFFFFFFFF )
			*a2 = (uint32_t)v4;
		else
			*a2 = -1;
	}
	return result;
}


int  readVarInt64(const uint8_t *beginptr, uint64_t * outvalue, const uint8_t *endptr)
{
	int count=0;
	const uint8_t* p = beginptr;
	bool ismax=false;
	uint64_t value=0;
	if ( !p ) {
		return 0;
	} 
	while ( !endptr || p < endptr )
	{
		uint8_t v=*p;
		if ((value >>32) > 0x1FFFFFF)
			ismax=true;

		value = (value<< 7) + (v & 0x7F);
		++count;		
		if ( v <= 127 )
			break;
		++p;
	}
	if ( endptr && p >= endptr )
	{
		count = 0;
	}
	else
	{
		if ( ismax )
		{
			value=(uint64_t)-1;
		}
		if ( outvalue )
		{
			*outvalue=value;
		}		
	}
	return count;
}

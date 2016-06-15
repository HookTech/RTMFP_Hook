#pragma once
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdexcept>

extern int readVarInt64(const uint8_t *beginptr, uint64_t * outvalue, const uint8_t *endptr);
extern int readVarInt32(const uint8_t *a1, uint32_t* a2, const uint8_t *a3);
extern int readVarLength(const uint8_t *buffer, uint32_t *outVar, const uint8_t *bufferEnd);
extern char hexchar(uint8_t value);
extern std::string hexUINT8(uint8_t value);
extern std::string hexBuffer(const uint8_t* buff,int length);
extern std::string GetIPFromUINT8(const uint8_t* buff);


class MyData{
private:
	uint8_t* data_;
	const size_t len_;
public:
	MyData():data_(NULL),len_(0){};

	MyData(const uint8_t* data,size_t len):len_(len){
		if(len>0){
			this->data_=new uint8_t[len];
			memcpy(this->data_,data,len);		
		} else{
			this->data_=NULL;
		}
	}

	MyData(const MyData& obj):len_(obj.len_) {
		if(len_>0){
			this->data_=new uint8_t[len_];
			memcpy(this->data_,obj.data_,obj.len_);		
		} else{
			this->data_=NULL;
		}
	}

	~MyData() throw() {
		delete[] data_;
	}

	uint8_t* data() const {return this->data_;};
	uint8_t* end() const {return this->data_+this->len_;};
	size_t size() const {return this->len_;};

	std::string toHexString() const{
		return hexBuffer(this->data_,len_);
	}

	static MyData readVarData(const uint8_t *&buffer,const uint8_t *bufferEnd){		
		if(buffer==bufferEnd)
			return MyData();
		if(buffer>bufferEnd)
			throw std::runtime_error("err");
		uint32_t size;
		int l=::readVarLength(buffer,&size,bufferEnd);
		if(l<=0) return MyData();	
		buffer+=l;
		MyData ret=MyData(buffer,size);	
		buffer+=size;
		return ret;
	}
};
class MyBuffer {
public:
	int vtable;
	int unknown;
	uint8_t *data;
	int length;
	int pos;
	char flags;

	/** from decompiler*/
	MyBuffer(uint8_t* data,int dataLength,char flags=0){
		this->flags &= 0xF8u;
		this->data=0;
		this->vtable =0xB4C8E0;
		this->length=0;
		this->pos=0;
		if(!this->initdata(data,dataLength,flags))
			throw std::runtime_error("init data fail");
	}

	uint8_t* getCurrentPtr(){
		return data+pos;
	}


	int getRemain(){
		return length-pos;
	}
	uint8_t* getEndPtr(){
		return data+length;
	}

	bool isEof(){
		return getCurrentPtr()<getEndPtr();
	}

	template <typename T>
	T readInt(){
		int newpos=pos+sizeof(T);
		if(newpos>length)
			throw std::runtime_error("eof exception");
		T ret=*(T*)getCurrentPtr();
		pos=newpos;
		return ret;
	}
	int readVarInt64(uint64_t * outvalue){
		int ret=::readVarInt64(data+pos,outvalue,data+length);
		if(ret)
			pos+=ret;
		return ret;
	}

	int readVarInt32(uint32_t * outvalue){
		int ret=::readVarInt32(data+pos,outvalue,data+length);
		if(ret)
			pos+=ret;
		return ret;
	}

	MyBuffer readVarData(){
		uint32_t size;
		int l=::readVarLength(data+pos,&size,data+length);
		if(l<=0)
			throw std::runtime_error("read var data error");
		pos+=l;
		auto begin=getCurrentPtr();
		pos+=size;
		return MyBuffer(begin,size,0);		
	}

	/** from decompiler*/
	~MyBuffer() throw (){
		if(this->flags & 1)
			free(this->data);
	}

	/** from decompiler*/
	char  initdata(void *data, int dataLength, char flags)
	{
		uint8_t *v6; 		
		if ( this->data )
			return 0;
		if ( flags & 1 && !data )
			return 0;
		this->pos = 0;
		this->length = dataLength;
		if ( data && flags & 1 )
		{
			this->data = (uint8_t *)data;
		}
		else
		{
			v6 = (uint8_t *)calloc(1u, dataLength);
			this->data = v6;
			if ( !v6 )
				return 0;
			this->flags |= 3u;
			if ( data )
				memcpy(v6, data, dataLength);
		}
		if ( flags & 2 )
			this->flags |= 1u;
		if ( flags & 4 )
			this->flags |= 2u;
		if ( flags & 8 )
			this->flags |= 4u;
		return 1;
	}

};
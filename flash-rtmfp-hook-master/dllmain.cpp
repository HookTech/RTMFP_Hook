#define NOMINMAX

#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <detours.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <stdint.h>
#include <algorithm>
#include <string>
#include<cstdio>

using namespace std;

#include "mybuffer.h"


int AckRangeBaseValue=0x000000;

template <class Type>
Type stringToNum(const std::string &str){//将string类型变量转换为常用的数值类型
    std::istringstream iss(str);
    Type num;
    iss >> num;
    return num;
}

#pragma comment( lib, "detours.lib" )
FILE* logfile;

/** 12个月份的缩写 */
const char* monthStr[]={"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug","Sep", "Oct", "Nov", "Dec"};


/**
* @param type 日志的类型，可以是任何字符串，不含双引号
* @param data 日志的内容
*/
static void logToFile(const std::string& type, const std::string& data)
{
	SYSTEMTIME st, lt;
	GetSystemTime(&st);	
	GetLocalTime(&lt);	
	std::ostringstream oss;	
	oss<<monthStr[lt.wMonth-1]<<" "<<lt.wDay<<", "<<lt.wYear<<" "<<lt.wHour<<":"<<lt.wMinute<<":"<<lt.wSecond<<"."<<lt.wMilliseconds;
	oss<<" "<<type<<" "<<data<<"\n";
	std::string msg=oss.str();
	fwrite(msg.c_str(),1,msg.length(),logfile);
	fflush(logfile);
}

/**
* 打开日志文件
* @filename
*/
void initLogFile(const char* filename){
	logfile=fopen(filename,"a+");	
}

/**
* 关闭日志文件 
*/
void closeLogFile(){	
	if(logfile!=NULL)
		fclose(logfile);
}

struct ChunkName{
	uint8_t chunkId;
	const char* name;
	void (*toStream)(std::ostream& os,const uint8_t* buff,int length);
};

void Print(std::ostream& oss ,int seqnum, int holes, int received)
{
	oss<<"holes="<<holes<<",";
    oss<<"receivednum="<<received<<",";
    oss<<"---"<<",";
    if (holes==1)
    {
		 oss<<"missing="<<seqnum+holes<<",";
	}
    else
     {
			oss<<"missing="<<seqnum+1<<".."<<seqnum+holes<<",";
	 }

    if (received==1)
	{
        oss<<"received="<<seqnum+holes+received<<",";
	}
    else
	{
        oss<<"received="<<seqnum+holes+1<<".."<<seqnum+holes+received<<",";
	}
}

int Compute(std::ostream& oss ,int seqnum,string str, int x, int flag)
{
	void Print(std::ostream& oss ,int seqnum, int holes, int received);
	int holes, received;
	char s[10];

	strcpy(s, str.substr(x, 2).c_str());
	holes = strtoul(s,  NULL, 16) + 1;

	strcpy(s, str.substr(x+2, 2).c_str());
	received = strtoul(s,  NULL, 16)+ 1;

	Print(oss ,seqnum, holes, received);
	
	if (flag)
	{
		seqnum += holes + received;
	}

	return seqnum;
        
}

void Loop(std::ostream& oss ,string  str, int x, int seqnum)
{
	int Compute(std::ostream& oss ,int seqnum,string str, int x, int flag);
    if (str.substr(x) != "")
	{
		seqnum = Compute(oss,seqnum, str, x, 1);
        if (str.substr(x + 4) != "")
		{
            seqnum = Compute(oss,seqnum, str, x + 4, 1);
			if (str.substr(x + 8) != "")
            {
				seqnum = Compute(oss,seqnum, str,  x + 8, 1);
                if (str.substr(x + 12) != "")
				{
                    seqnum = Compute(oss,seqnum, str, x + 12, 1);
					 if (str.substr(x + 16) != "")
					{
						seqnum = Compute(oss,seqnum, str, x + 16, 0);
				    }
			    }
			}
		}
	}
}

int Ackrange(std::ostream& oss ,std::string str)
{
	void Loop(std::ostream& oss ,string str, int x, int seqnum);
	int seqnum;
	int length=str.length();
	int a, b, c, a1,b1;
	char s[10]={0};
	if ((length <= 6) || (str.substr(2,2) == "00"))
	{
		oss<<"This is flow exception!"<<",";
		return 0;
	}
	
	if (str[6] < '8')    //two valid place
	{
		  strcpy(s, str.substr(6, 2).c_str());
		  seqnum = strtoul(s,  NULL, 16);
		  Loop(oss ,str, 8,  seqnum);
	}
	
	else if( (str[6] >= '8')  && ((length-10)%4==0))  //four valid place
	{
		
		strcpy(s, str.substr(6, 2).c_str());
		//oss<<s<<",";
	    a = strtoul(s,  NULL, 16);
		a1 = (a-128) * 128;
	

		strcpy(s, str.substr(8, 2).c_str());
	    b = strtoul(s,  NULL, 16);

        seqnum = a1 + b;
		//oss<<a<<"-"<<b<<"-"<<a1<<"-"<<seqnum<<",";
        Loop(oss ,str, 10,  seqnum);
		  
	}

	else if((str[6] >= '8')  && ((length-12)%4==0))  //six valid place
	{
		strcpy(s, str.substr(6, 2).c_str());
		a = strtoul(s,  NULL, 16);

		strcpy(s, str.substr(8, 2).c_str());
	    b = strtoul(s,  NULL, 16);

		strcpy(s, str.substr(10, 2).c_str());
	    c = strtoul(s,  NULL, 16);

		a1 = (a-128) * 128 * 128;
        b1 = (b-128) * 128;
		seqnum = a1 + b1 + c;
		Loop(oss ,str, 12,  seqnum);
	}
	return  seqnum;
}

void printToStream(std::ostream& os,const uint8_t* buff,int length){
	//os<<hexBuffer(buff,length);
	os<<"[byte length:"<<length<<"]";
}

void printRawStream(std::ostream& os,const uint8_t* buff,int length){
	os<<hexBuffer(buff,length);
}

void printIHelloChunk(std::ostream& oss,const uint8_t* buff,int length){	
	oss<<"{";
	const uint8_t* end=buff+length;
	MyData epdArray=MyData::readVarData(buff,end);
	if(epdArray.data()){
		//logToFile("debug","hasEPDArray");
		const uint8_t* rdptr=epdArray.data();
		const uint8_t* end2=epdArray.end();
		while(true){
			MyData epd=MyData::readVarData(rdptr,end2);
			if(epd.size()==0) break;			
			int epdType=*epd.data();
			oss<<" epdType 0x"<<hexUINT8(epdType);
			if(epdType==0x0A)
				oss<<" epd:"<<std::string(epd.data()+1,epd.end());
			else
				oss<<" epd:"<<hexBuffer(epd.data()+1,epd.size()-1);
		}
	}	
	oss<<" tag:"<<hexBuffer(buff,end-buff);
	oss<<"}";	
}

void printFIHelloChunk(std::ostream& oss,const uint8_t* buff,int length){
	oss<<"{";
	const uint8_t* end=buff+length;
	//logToFile("Debug","Try to Get FIHelloInfo");
	int ll=(int)(*buff);
	oss<<" EpdLength: "<<ll;//第三个字段
	buff++;
	oss<<" Edp: "<<hexBuffer(buff,ll);
	buff=buff+ll;
	oss<<" ReplyAddress: "<<GetIPFromUINT8(buff);//IP字段
	buff=buff+7;
	oss<<" Tag: "<<hexBuffer(buff,end-buff);//第六个字段
	oss<<"}";
}

void printRHelloCookieChangeChunk(std::ostream& oss,const uint8_t* buff,int length){
	oss << "{";
	const uint8_t* end=buff+length;
	int ll=(int)(*buff);
	buff=buff+1;
	oss << "oldCookie:" << hexBuffer(buff,ll);
	buff=buff+ll;
	oss << "newCookie" << hexBuffer(buff,end-buff);
	oss << "}";
}

void printRedirectChunk(std::ostream& oss,const uint8_t* buff,int length){
	oss<<"{";
	const uint8_t* end=buff+length;
	//logToFile("Debug","Try to Get RedirectInfo");
	int ll=(int)(*buff);
	oss<<" TagLength: "<<ll;
	buff++;
	oss<<" TagEcho: "<<hexBuffer(buff,ll);
	buff=buff+ll;
	float addcount=(float)(end-buff)/7.0;
	oss<< " RedirectCounts: "<<addcount;
	for(int i=1;i<=addcount;i++){
		oss<<" RedirectDestination"<<i<<": "<<GetIPFromUINT8(buff);
		buff+=7;
	}
	oss<<"}";
}

void printRHelloChunk(std::ostream& oss,const uint8_t* buff,int length){	
	oss<<"{";
	const uint8_t* end=buff+length;
	MyData tag=MyData::readVarData(buff,end);
	MyData cookie=MyData::readVarData(buff,end);
	oss<<"tag: "<<tag.toHexString()<<" cookie:"<<cookie.toHexString()<<" cert:"<<hexBuffer(buff,end-buff);
	oss<<"}";	
}

void printIIKeyingChunk(std::ostream& oss,const uint8_t* buff,int length){	
	oss<<"{";
	const uint8_t* end=buff+length;
	uint32_t sid;
	memcpy(&sid,buff,sizeof(sid));
	buff+=sizeof(sid);
	MyData cookie=MyData::readVarData(buff,end);
	MyData cert=MyData::readVarData(buff,end);
	MyData skic=MyData::readVarData(buff,end);
	int sig=*buff;
	oss<<"sid:"<<sid<<" cookie: "<<cookie.toHexString()<<" cert:"<<cert.toHexString()<<" skic:"<<skic.toHexString()<<" sig:"<<sig;
	oss<<"}";	
}

void printRIKeyingChunk(std::ostream& oss,const uint8_t* buff,int length){	
	oss<<"{";
	const uint8_t* end=buff+length;
	uint32_t sid;
	memcpy(&sid,buff,sizeof(sid));
	buff+=sizeof(sid);	
	MyData skrc=MyData::readVarData(buff,end);
	int sig=*buff;
	oss<<"sid:"<<sid<<" skrc:"<<skrc.toHexString()<<" sig:"<<sig;
	oss<<"}";	
}

void printDataChunk(std::ostream& oss,const uint8_t* buff,int length){	
	oss<<"{";
	const uint8_t* end=buff+length;
	uint8_t flag=*buff++;
	uint64_t flowID,sequenceNumber,fsnOffset;
	size_t size;
	size=readVarInt64(buff,&flowID,end);
	buff+=size;
	readVarInt64(buff,&sequenceNumber,end);
	buff+=size;
	readVarInt64(buff,&fsnOffset,end);
	buff+=size;
	oss<<"flag:0x"<<hexUINT8(flag)<<", flowID:"<<flowID<<",sequenceNumber:"<<sequenceNumber<<",fsnOffset:"<<fsnOffset;
	if(flag & 0x80){
		while(true){
			MyData option=MyData::readVarData(buff,end);
			if(option.size()==0) break;
			oss<<" option:"<<option.toHexString();
		}
	}
	oss<<" Data: [byte length:"<< end-buff << "]";//hexBuffer(buff,end-buff);	
	oss<<"}";	
}

void printAckRangesChunk(std::ostream& oss,const uint8_t* buff,int length){
	oss << "{";
	const uint8_t* end=buff+length;
	stringstream ss;
	ss << hexBuffer(buff,length);
	oss<<ss.str() << "; ";
	int cumack=Ackrange(oss ,ss.str());
	oss<<"cumack="<<cumack << ", ";
	oss << "}";
}

ChunkName chunkNames[]={{0x7f,"Fragment"},
{0x30,"IHello",printIHelloChunk},
{0xF,"FIHello",printFIHelloChunk},
{0x70,"RIHello",printRHelloChunk},
{0x71,"Redirect",printRedirectChunk},
{0x79,"RHelloCookieChange",printRHelloCookieChangeChunk},
{0x38,"IIKeying",printIIKeyingChunk},
{0x78,"RIKeying",printRIKeyingChunk},
{0x1,"Ping",printToStream},
{0x41,"PingReply",printToStream},
{0x10,"UserData",printDataChunk},
{0x11,"NextUserData",printToStream},
{0x50,"AckBitmap",printToStream},
{0x51,"AckRanges",printAckRangesChunk},
{0x18,"BufferProbe",printToStream},
{0x5E,"FlowException",printToStream},
{0xC,"CloseRequest",printToStream},
{0x4C,"CloseAck",printToStream},
};//主要包的type并对相应行为做映射
const size_t chunkTypesCount=sizeof(chunkNames)/sizeof(chunkNames[0]);
static_assert(18 == chunkTypesCount,"chunk types length error");


static std::string jsonArray(const uint8_t* buff,int length){
	std::ostringstream oss;
	oss<<"[";
	for(int i=0;i!=length;++i){
		oss<<(uint32_t)buff[i];
		if(i!=length-1)
			oss<<",";
	}
	oss<<"]";
	return oss.str();
}


//only used for detours inject
__declspec(dllexport) void __cdecl dummyfunc(void){

}




/**
* 地址信息
*/
class SockAddr{
public:
	int vtable;
	void* unknown1;	
	union {
		ADDRESS_FAMILY  sin_family;
		sockaddr_in v4;
		sockaddr_in6 v6;
	};
	int addrlen;
};

static_assert(sizeof(SockAddr)==0x28,"size error");
std::string sockAddrToString(SockAddr* a4){
	char ipstringbuffer[128];
	DWORD ipstringbufferLength=128;

	size_t addrlen;
	if(a4->sin_family==AF_INET) addrlen=sizeof(sockaddr_in);
	else if(a4->sin_family==AF_INET6) addrlen=sizeof(sockaddr_in6);
	else throw std::runtime_error("unknown addrtype");
	WSAAddressToStringA((LPSOCKADDR)&a4->v4,addrlen,NULL,ipstringbuffer,&ipstringbufferLength);
	return std::string(ipstringbuffer);
}

struct ListItem
{
	ListItem *next;
	ListItem *prev;
	void *itemptr;
	char flag;
};

struct Data
{
	int *vtable;
	int unknown;
	uint8_t *data;
	int length;
	int pos;
	char flags;
};

struct RtmfpList
{
	int vtable;
	int ref;
	int cap;
	int unknown;
	int size;
	int (__cdecl *onAdd)(int);
	int (__cdecl *onDel)(int);
	ListItem *begin;
	char buf[64];
};

struct RandomNumberGenerator
{
	int vtable;
	int ref;
	void *randomProvider;
};


struct BasicCryptoIdentity
{
	int vtable;
	int ref;
	Data *peerid;
	Data *hexPeerID;
	Data *data3;
	Data *url;
};

struct BasicCryptoCert
{
	int vtable;
	int ref;
	Data cert;
	int len;
	Data *p1;
	int v1;
	int v2;
	int v3;
	int v4;
	int v5;
	int v6;
	char flag;
	char _padding[3];
};

struct SHA256Context
{
	char data[120];
};


struct HMACSHA256Context
{
	int vtable;
	int ref;
	SHA256Context c1;
	SHA256Context c2;
	SHA256Context c3;
};


struct IndexSet
{
	int vtable;
	int ref;
	RtmfpList list;
};



class BasicCryptoKey;

struct BasicCryptoAdapter
{
	int vtable;
	Data *d1;
	Data d2;
	RandomNumberGenerator *rand;
	BasicCryptoKey *key;
	BasicCryptoIdentity id;
	BasicCryptoCert cert;
	int v1;
	bool b1;
	int v2;
	int v3;
	int v4;
	int v5;
	int v6;
};

struct Dictionary
{
	char data[48];
};

struct Set
{
	char data[48];
};

struct InstanceTimerList
{
	char data[64];
};

struct Instance;


struct NoSession
{
	int vtable;
	int ref;
	Instance *instance;
	RtmfpList nosessionItems;
	void processInput(SockAddr *addressInfo, int sessionid, int interfaceid);

};

#include "func_pointers.inc"

std::string payloadToString(const uint8_t* data,const size_t len){//主要函数，把payload转换成为string输入oss
	std::ostringstream oss;
	const uint8_t* end=data+len;
	while(data!=end){
		uint8_t chunkId=*data++;
		if(chunkId==0x00 || chunkId==0xFF) break;
		uint32_t chunkLen=*data++;
		chunkLen=chunkLen<<8 | *data++;		
		auto end=chunkNames+chunkTypesCount;
		auto ret=std::find_if(chunkNames,end,[chunkId](const ChunkName& n){return n.chunkId==chunkId;});	
		if(ret!=end){
			oss<<" "<<ret->name<<":";
			ret->toStream(oss,data,chunkLen);			
		}
		else 
			oss<<"unknownChunkType "<<chunkId;

		data+=chunkLen;
	}
	return oss.str();
}

struct Instance
{
	int vtable;
	int ref;
	void *rtmfpPlatformAdapter;
	void *rtmpMetadataAdapter;
	BasicCryptoAdapter *basicCryptoAdapter;
	void *p1;
	int v1;
	RtmfpList interfaces;
	RtmfpList sessions;
	Dictionary dic1;
	Dictionary dic2;
	Set s1;
	Dictionary dic3;
	Dictionary dic4;
	InstanceTimerList timers;
	RtmfpList l1;
	NoSession nosession;
	char rand1[64];
	char rand2[32];
	int v2;
	int v3;
	int v4;
	unsigned char flags;
	char gap_345[3];
	int timestamp;
	int timestampEcho;
	char recvbuf[8192];
	char *ptr;
	size_t len;
	int v5;
	int pos;
	char sendbuf[8196];
	size_t v7;
	Data d1;
	int v8;
	void *p2;
	int v9;
	int v10;
	int v11;
	int v12;
	int v13;
	int v14;
	bool b1;
	bool b2;
	char gap_43A2[2];
	int v15;
	bool v16;
	bool v17;
	char gap_43AA[2];
	int v18;
	int fillPacketHeader(int a1,int sessionid){		
		std::ostringstream oss;		
		oss<<"sessionid:"<<sessionid<<",flags: "<<hexchar(this->flags>>4)<<hexchar(this->flags&0xF)
			<<",data: "<<payloadToString((unsigned char*)this->ptr,this->len);		
		std::string msg=oss.str();
		logToFile("createPacket",msg);
		int ret=oldfillPacketHeader(this,0,a1,sessionid);
		return ret;
	}
};


void NoSession::processInput(SockAddr *addressInfo, int sessionid, int interfaceid){
	std::ostringstream oss;		
	oss<<"sessionid:"<<sessionid<<",addr:"<<sockAddrToString(addressInfo)<<",chunks: "<<payloadToString((uint8_t*)this->instance->ptr,this->instance->len);		
	std::string msg=oss.str();
	logToFile("NoSesionProcessInput",msg);
	oldNoSessionProcessInput(this,0,addressInfo,sessionid,interfaceid);
}


/**
* CCMEAESContext
*/
class C00B4F258{
public:
	//construct a key. 
	char func007AE1E1(const unsigned char *key, int keyType, int direction){
		size_t keylength;
		if ( keyType )
		{
			if ( keyType == 1 )
			{
				keylength = 192;
			}
			else
			{
				if (keyType != 2){
					//unexpected key type!!!
					return 0;
				}
				keylength = 256;
			}
		}
		else
		{
			keylength = 128;
		}
		keylength=keylength/8;
		std::ostringstream oss;
		oss<<"key: "<<hexBuffer(key,keylength)<<",direction:"<<direction;
		logToFile("keyinfo",oss.str());	
		char ret = oldfunc007AE1E1(this, 0, key, keyType, direction);
		return ret;
	}
};



/*char (__fastcall  *oldfunc7A6807)(void* pthis,int dummy,char *dhpublicnumber, unsigned int length)=
	(char (__fastcall*)(void* pthis,int dummy,char *dhpublicnumber, unsigned int length))0x007A6807;*/

/**
* DiffieHellmanContext::DiffieHellmanContext vtable=00B4C8E8
*/
class DiffieHellmanContext{
public:
	int vtable;
	int ref;
	int unknown1;
	MyBuffer b1;
	MyBuffer b2;
	MyBuffer b3;
	MyBuffer b4;

	/*
	char func7A6807(char *dhpublicnumber, unsigned int length){
	int ret=oldfunc7A6807(this,0,dhpublicnumber,length);
	std::ostringstream oss;
	oss<<"{type: \"dhinfo\",data: {b4:"<<hexBuffer(this->b4.data,this->b4.length)<<"}}";
	std::string msg=oss.str();
	logToFile(msg.c_str());
	return ret;
	}*/
};



/**
* RTMFP::BasicCryptoKey vtable=00B4C820
*/
class BasicCryptoKey{
public:
	int vtable;
	int ref;
	int v1;
	int v2;
	DiffieHellmanContext *info;
	int v4;
	HMACSHA256Context *hmacContext;
	int v6;
	int v7;
	HMACSHA256Context *hmacContext2;
	int v9;
	int v10;
	int writeSSEQ;
	int v12;
	__int64 seq;
	int v15;
	IndexSet *v16;
	Data *initiatorNonce;
	Data *responderNonce;
	uint8_t nearNonce[32];
	uint8_t farNonce[32];


	char func007A17EA(uint8_t *dhpublicnumber, int length, int keyType){
		std::ostringstream oss;
		oss<<"dhpublicnumber:"<<hexBuffer(dhpublicnumber,length)
			<<",skic:"<<hexBuffer(this->initiatorNonce->data,this->initiatorNonce->length)
			<<",skrc:"<<hexBuffer(this->responderNonce->data,this->responderNonce->length)
			<<",dhprime:"<<hexBuffer(this->info->b1.data,this->info->b1.length)
			<<",dhprivatekey:"<<hexBuffer(this->info->b2.data,this->info->b2.length);
		char ret=oldfunc7A17EA(this,0,dhpublicnumber,length,keyType);
		oss<<",farNonce:"<<hexBuffer(this->farNonce,sizeof(this->farNonce))
			<<",nearNonce:"<<hexBuffer(this->nearNonce,sizeof(this->nearNonce));
		std::string msg=oss.str();
		logToFile("secinfo",msg.c_str());

		return ret;
	}
};

struct SparseArray
{
	char data[48];
};

struct SumList
{
	int vtable;
	int ref;
	int cap;
	int unknown;
	int unknown2;
	int (__cdecl *onAdd)(int);
	int (__cdecl *onDel)(int);
	ListItem *begin;
	char buf[64];
	int unknown3;
	int unknown4;
};


struct Session
{
	int vtable;
	int ref;
	Instance *instance;
	int v1;
	int v2;
	int responderSessionID;
	SockAddr addr;
	int interfaceId;
	int v4;
	int v5;
	int v6;
	int v7;
	int v8;
	int v9;
	int v10;
	int v11;
	int v12;
	int v13;
	int v14;
	int v15;
	int v16;
	int v17;
	int v18;
	int v19;
	int v20;
	int v21;
	int v22;
	int timestamp;
	int timestampEcho;
	int v23;
	int v24;
	Data *epd;
	Data *tag;
	Data *initiatorNonce;
	int v25;
	int v26;
	int v27;
	int v28;
	int v29;
	int v30;
	int v31;
	int v32;
	int v33;
	int v34;
	int v35;
	int v36;
	int v37;
	int v38;
	int v39;
	void *v40;
	int v41;
	int v42;
	int v43;
	RtmfpList list1;
	SparseArray flows;
	Set set1;
	SumList sl;
	RtmfpList lists[8];
	char f1;
	char f2;
	char f3;
	char gap_523[1];
	int vend;

	void processInput(SockAddr *addressInfo, int sessionid, int interfaceid){
		std::ostringstream oss;		
		oss<<"sessionid:"<<sessionid<<",addr:"<<sockAddrToString(addressInfo)<<",data: "<<payloadToString((unsigned char*)this->instance->ptr,this->instance->len);		
		std::string msg=oss.str();
		logToFile("SesionProcessInput",msg);
		oldSessionProcessInput(this,0,addressInfo,sessionid,interfaceid);
	}

};


void logerror(const char* file,long line,const std::string& msg){
	std::ostringstream oss;
	oss<<"error:\""<<msg<<"\",file: \""<<file<<"\",line: "<<line;
	std::string err=oss.str();
	logToFile("error",err.c_str());
}

#define LOG_ERROR(msg) {logerror(__FILE__,__LINE__,msg);}

/**
* 网络管理器。它的构造函数会调用WSAStartup
*/
class C00B0C408{
	int vtable;
	int ref;
	int socket;
public:	
	int func5DD293(uint8_t *buf, int len, int port, int addressFamily){
		std::ostringstream oss;		
		oss<<"socket:"<<this->socket<<",port:"<<port<<",addressFamily:"<<addressFamily<<",data: "<<hexBuffer(buf,len);		
		std::string msg=oss.str();
		logToFile("send2",msg);
		return oldfunc5DD293(this,0,buf,len,port,addressFamily);
	}

	int func5DD07D(uint8_t *buf, int len, SockAddr* a4){		
		std::ostringstream oss;			
		oss<<"socket:"<<this->socket<<",addr:\""<<sockAddrToString(a4)<<"\",data:"<<"[ byte length: "<<len<<"]";//hexBuffer(buf,len);				
		logToFile("send",oss.str());
		return oldfunc5DD07D(this,0,buf,len,a4);
	}	
	int func5DCFFE(uint8_t *buf, int len, SockAddr* a4){
		int ret=oldfunc5DCFFE(this,0,buf,len,a4);	
		if(ret>0){			
			std::ostringstream oss;
			oss<<"socket:"<<this->socket<<",addr:\""<<sockAddrToString(a4)<<"\",data:"<<"[ byte length: "<<len<<"]";//hexBuffer(buf,ret);	
			logToFile("recv",oss.str());			
		}
		return ret;
	}
};


template <typename T>
union CONV{	
	void* p;
	T orig;
};

template <typename T>
static void* toPVOID(T t){
	CONV<decltype(t)> c;
	c.orig = t;
	return c.p;
}

static void doRegister(){
	LONG error;
	DetourTransactionBegin();
	DetourUpdateThread( GetCurrentThread() );
	
	


	//记录key
	DetourAttach(&(PVOID &)oldfunc007AE1E1, toPVOID(&C00B4F258::func007AE1E1));

	//计算AES key
	DetourAttach(&(PVOID &)oldfunc7A17EA, toPVOID(&BasicCryptoKey::func007A17EA));
	//发送局域网UDP广播
	DetourAttach(&(PVOID &)oldfunc5DD293, toPVOID(&C00B0C408::func5DD293));
	//收到UDP包
	DetourAttach(&(PVOID &)oldfunc5DCFFE, toPVOID(&C00B0C408::func5DCFFE));
	//发送UDP包
	DetourAttach(&(PVOID &)oldfunc5DD07D, toPVOID(&C00B0C408::func5DD07D));

	DetourAttach(&(PVOID &)oldfillPacketHeader, toPVOID(&Instance::fillPacketHeader));
	DetourAttach(&(PVOID &)oldNoSessionProcessInput, toPVOID(&NoSession::processInput));
	DetourAttach(&(PVOID &)oldSessionProcessInput, toPVOID(&Session::processInput));

	error=DetourTransactionCommit(); 
	if(error==NO_ERROR){
		logToFile("begin","");
	}
}

static void doUnRegister(){
	LONG error;
	DetourTransactionBegin();
	DetourUpdateThread( GetCurrentThread() );
	//DetourDetach( &(PVOID &)oldfunc7A6807,(PVOID)(&(PVOID&) DiffieHellmanContext::func7A6807));
	DetourDetach(&(PVOID &)oldfunc7A17EA, toPVOID(&BasicCryptoKey::func007A17EA));
	DetourDetach(&(PVOID &)oldfunc5DD293, toPVOID(&C00B0C408::func5DD293));
	DetourDetach(&(PVOID &)oldfunc5DCFFE, toPVOID(&C00B0C408::func5DCFFE));
	DetourDetach(&(PVOID &)oldfunc5DD07D, toPVOID(&C00B0C408::func5DD07D));
	DetourDetach(&(PVOID &)oldfunc007AE1E1, toPVOID(&C00B4F258::func007AE1E1));
	DetourDetach(&(PVOID &)oldfillPacketHeader, toPVOID(&Instance::fillPacketHeader));
	DetourDetach(&(PVOID &)oldNoSessionProcessInput, toPVOID(&NoSession::processInput));
	DetourDetach(&(PVOID &)oldSessionProcessInput, toPVOID(&Session::processInput));
	error=DetourTransactionCommit(); 
	logToFile("end","");
}

BOOL APIENTRY DllMain( HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
	)
{	

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		initLogFile("flash.log");		
		doRegister();
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		doUnRegister();
		closeLogFile();
		break;
	}
	return TRUE;
}


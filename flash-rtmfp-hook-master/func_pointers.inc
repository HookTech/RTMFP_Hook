auto oldfunc007AE1E1=(char  (__fastcall *)(void* pthis,int dummy,const unsigned char *key, int keyType, int direction))0x0092BB2C;

auto oldfunc7A17EA=
	(int (__fastcall  *)(void* pthis,int dummy,uint8_t *dhpublicnumber, int length, int keyType))0x0091F12E;

auto oldfunc5DCFFE=
	(int (__fastcall *)(void* pthis,int dummy,uint8_t *buf, int len, SockAddr* a4))0x006435F8;

auto oldfunc5DD07D=
	(int (__fastcall *)(void* pthis,int dummy,uint8_t *buf, int len, SockAddr* a4))0x00643677;

auto oldfunc5DD293=
	(int (__fastcall *)(void* pthis,int dummy,uint8_t *buf, int len, int port, int addressFamily))0x0064388D;

auto oldfillPacketHeader=(char  (__fastcall *)(void* pthis,int dummy,int a1,int sessionid))0x0091CE80;

auto oldNoSessionProcessInput
	=(void  (__fastcall *)(void* pthis,int dummy,SockAddr *addressInfo, int sessionid, int interfaceid))0x0093072A;

auto oldSessionProcessInput
	=(void  (__fastcall *)(void* pthis,int dummy,SockAddr *addressInfo, int sessionid, int interfaceid))0x00926C82;

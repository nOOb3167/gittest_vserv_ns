#ifndef _NS_VSERV_NET_MAIN_H_
#define _NS_VSERV_NET_MAIN_H_

#include <cstdint>
#include <map>
#include <memory>
#include <vector>

#include <enet/enet.h>

#include <vserv/UDPSocket.h>

#define MYMIN(a, b) ((a) < (b) ? (a) : (b))

#define GS_DUMMY(...) do {} while(0)

#define VSERV_NETWORKPACKET_SIZE_INCREMENT 4096

#define VSERV_MGMT_CLIENT_MAX 128

class VServMgmt;

struct networkpacket_buf_len_tag_t {};
struct networkpacket_cmd_tag_t {};

class NetworkPacket
{
public:
	NetworkPacket(uint8_t *data, size_t data_len, networkpacket_buf_len_tag_t);
	NetworkPacket(uint8_t cmd, networkpacket_cmd_tag_t);

	~NetworkPacket() = default;

	NetworkPacket(const NetworkPacket &a)            = delete;
	NetworkPacket& operator=(const NetworkPacket &a) = delete;
	NetworkPacket(NetworkPacket &&a)            = default;
	NetworkPacket& operator=(NetworkPacket &&a) = default;

	uint8_t * getDataPtr();
	size_t getDataSize();

	uint8_t readU8(const uint8_t *data);
	void writeU8(uint8_t *data, uint8_t i);

	uint16_t readU16(const uint8_t *data);
	void writeU16(uint8_t *data, uint16_t i);

	uint32_t readU32(const uint8_t *data);
	void writeU32(uint8_t *data, uint32_t i);

	void checkReadOffset(uint32_t from_offset, uint32_t field_size);
	void checkDataSize(uint32_t field_size);

	NetworkPacket& operator>>(uint8_t& dst);
	NetworkPacket& operator<<(uint8_t src);

	NetworkPacket& operator>>(uint16_t& dst);
	NetworkPacket& operator<<(uint16_t src);

	NetworkPacket& operator>>(uint32_t& dst);
	NetworkPacket& operator<<(uint32_t src);

private:
	std::vector<uint8_t> m_data;
	size_t m_off;
};

class VServRespond
{
public:
	void respondOneshot(NetworkPacket packet, Address addr);

protected:
	virtual void virtualRespond(NetworkPacket packet, Address *addr_vec, size_t addr_num) = 0;
};

class VServRespondMgmt : public VServRespond
{
	typedef ::std::unique_ptr<ENetPacket, void(*)(ENetPacket *pkt)> unique_ptr_enetpacket;

public:
	VServRespondMgmt(VServMgmt *mgmt, ENetPeer *peer);

	static void deleteENetPacket(ENetPacket *pkt);

protected:
	void virtualRespond(NetworkPacket packet, Address *addr_vec, size_t addr_num);

private:
	VServMgmt * m_mgmt;
	ENetPeer *  m_peer;
};

class VServMgmt
{
	typedef ::std::unique_ptr<ENetHost, void(*)(ENetHost *host)> unique_ptr_enethost;
	typedef ::std::unique_ptr<ENetEvent, void(*)(ENetEvent *evt)> unique_ptr_enetevent;

public:
	VServMgmt(size_t port);

	std::map<Address, ENetPeer *, address_less_t> & getAddrPeerMap();

	void funcThread();

	static ENetEvent * createEmptyENetEvent();

	static void deleteENetHost(ENetHost *host);
	static void deleteENetEvent(ENetEvent *evt);

protected:
	virtual void virtualProcessPacket(NetworkPacket *packet, VServRespond *respond, Address addr) = 0;

private:
	ENetAddress  m_addr;
	unique_ptr_enethost m_host;
	std::unique_ptr<std::thread> m_thread;

	std::map<Address, ENetPeer *, address_less_t> m_addr_peer_map;
};

class VServCtl
{
public:
	VServCtl(std::unique_ptr<VServMgmt> mgmt);

private:
	std::unique_ptr<VServMgmt> m_mgmt;
};

void vserv_start_crank(size_t port);

#endif /* _NS_VSERV_NET_MAIN_H_ */

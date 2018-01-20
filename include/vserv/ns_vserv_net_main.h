#ifndef _NS_VSERV_NET_MAIN_H_
#define _NS_VSERV_NET_MAIN_H_

#include <algorithm>
#include <array>
#include <cstdint>
#include <map>
#include <memory>
#include <thread>
#include <utility>
#include <vector>

#include <enet/enet.h>

#include <vserv/UDPSocket.h>

#define MYMIN(a, b) ((a) < (b) ? (a) : (b))

#define GS_DUMMY(...) do {} while(0)

#define VSERV_NETWORKPACKET_SIZE_INCREMENT 4096
#define VSERV_UDPSIZE_MAX 4096

#define VSERV_WORK_CLIENT_MAX  128
#define VSERV_MGMT_CLIENT_MAX  128
#define VSERV_BOTH_CLIENT_CEIL 128

#define VSERV_USER_TIMEOUT_CHECK_MS 1000
#define VSERV_USER_TIMEOUT_MS 5000

class VServMgmt;

struct networkpacket_buf_len_tag_t {};
struct networkpacket_cmd_tag_t {};

class ProtocolExc : public std::runtime_error
{
public:
	ProtocolExc(const char *msg);
};

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
	size_t getRemainingSize();

	uint8_t readU8(const uint8_t *data);
	void writeU8(uint8_t *data, uint8_t i);

	uint16_t readU16(const uint8_t *data);
	void writeU16(uint8_t *data, uint16_t i);

	uint32_t readU32(const uint8_t *data);
	void writeU32(uint8_t *data, uint32_t i);

	void checkReadOffset(uint32_t from_offset, uint32_t field_size);
	void checkDataSize(uint32_t field_size);

	const char * inSizedStr(size_t len);
	void outSizedStr(const char *str, size_t len);

	void rewriteU16At(size_t off, uint16_t i, uint16_t *opt_old_val);

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
	void respondMulti(NetworkPacket packet, Address *addr_vec, size_t addr_num);
	void respondMultiId(NetworkPacket packet, uint16_t *id_vec, size_t id_num, const std::map<uint16_t, Address> &uid_addr_map);

protected:
	virtual void virtualRespond(NetworkPacket packet, Address *addr_vec, size_t addr_num) = 0;
};

class VServWork
{
public:
	class Write
	{
	public:
		Write(NetworkPacket packet, Address *addr_vec, size_t addr_num);

		NetworkPacket m_packet;
		std::array<Address, VSERV_WORK_CLIENT_MAX> m_addr;
		size_t m_addr_num;
		size_t m_addr_idx;
	};

	VServWork(size_t port);

	void funcThread();

protected:
	virtual void virtualProcessPacket(NetworkPacket *packet, VServRespond *respond, Address addr) = 0;

private:
	Address m_addr;
	std::unique_ptr<UDPSocket>   m_sock;
	std::unique_ptr<std::thread> m_thread;

	std::shared_ptr<std::deque<VServWork::Write> > m_writequeue;
};

class VServRespondWork : public VServRespond
{
public:
	VServRespondWork(const std::shared_ptr<std::deque<VServWork::Write> > & writequeue);

protected:
	void virtualRespond(NetworkPacket packet, Address *addr_vec, size_t addr_num);

private:
	std::shared_ptr<std::deque<VServWork::Write> > m_writequeue;
};

class VServMgmt
{
	typedef ::std::unique_ptr<ENetHost, void(*)(ENetHost *host)> unique_ptr_enethost;
	typedef ::std::unique_ptr<ENetEvent, void(*)(ENetEvent *evt)> unique_ptr_enetevent;

public:
	VServMgmt(size_t port);

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

	std::shared_ptr<std::map<Address, ENetPeer *, address_less_t> > m_addr_peer_map;
};

class VServRespondMgmt : public VServRespond
{
	typedef ::std::unique_ptr<ENetPacket, void(*)(ENetPacket *pkt)> unique_ptr_enetpacket;

public:
	VServRespondMgmt(const std::shared_ptr<std::map<Address, ENetPeer *, address_less_t> > &addr_peer_map);

	static void deleteENetPacket(ENetPacket *pkt);

protected:
	void virtualRespond(NetworkPacket packet, Address *addr_vec, size_t addr_num);

private:
	std::shared_ptr<std::map<Address, ENetPeer *, address_less_t> > m_addr_peer_map;
};

class VServCtl
{
public:
	VServCtl(std::unique_ptr<VServWork> work, std::unique_ptr<VServMgmt> mgmt);

private:
	std::unique_ptr<VServWork> m_work;
	std::unique_ptr<VServMgmt> m_mgmt;
};

void vserv_start_crank(size_t port_work, size_t port_mgmt);

#endif /* _NS_VSERV_NET_MAIN_H_ */

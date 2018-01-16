#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <utility>

// FIXME: #include <arpa/inet.h> for ntohl on NIX

#include <enet/enet.h>

#define MYMIN(a, b) ((a) < (b) ? (a) : (b))

#define VSERV_ADDRESS_ADDR_SIZE 16

#define VSERV_MGMT_CLIENT_MAX 128

struct address_ipv4_tag_t {};
struct networkpacket_buf_len_tag_t {};

class Address
{
public:
	Address(uint8_t family, uint16_t port, uint32_t addr, address_ipv4_tag_t) :
		m_family(family),
		m_port(port),
		m_addr()
	{
		memset(m_addr, '\0', VSERV_ADDRESS_ADDR_SIZE);
		memcpy(m_addr, &addr, sizeof (uint32_t));
	}

private:
	uint8_t  m_family;
	uint16_t m_port;
	uint8_t  m_addr[VSERV_ADDRESS_ADDR_SIZE];

	friend struct address_less_t;
};

class NetworkPacket
{
public:
	NetworkPacket(uint8_t *data, size_t data_len, networkpacket_buf_len_tag_t) :
		m_data((const char *) data, data_len),
		m_off(0)
	{}

	inline uint8_t readU8(uint8_t data)
	{
		return (m_data[0] << 0);
	}

	void checkReadOffset(uint32_t from_offset, uint32_t field_size)
	{
		if (from_offset + field_size > m_data.size())
			throw std::runtime_error("packet data size");
	}

	NetworkPacket& NetworkPacket::operator>>(uint8_t& dst)
	{
		checkReadOffset(m_off, 1);
		dst = readU8(m_data[m_off++]);
		return *this;
	}

private:
	std::string m_data;
	size_t m_off;
};

struct address_less_t {
	bool operator()(const Address &a, const Address &b) const
	{
		bool n0 = a.m_family < b.m_family;
		bool n1 = a.m_port < b.m_port;
		bool n2cmp = memcmp(a.m_addr, b.m_addr, VSERV_ADDRESS_ADDR_SIZE);
		bool n2 = n2cmp < 0;
		return a.m_family != b.m_family ? n0 : (a.m_port != b.m_port ? n1 : (n2cmp != 0 ? n2 : false));
	}
};

Address vserv_enetaddress_to_address(ENetAddress enet_addr)
{
	return Address(AF_INET, enet_addr.port, ntohl(enet_addr.host), address_ipv4_tag_t());
}

class VServRespond
{
};

class VServRespondMgmt : public VServRespond
{
public:
	VServRespondMgmt(VServMgmt *mgmt, ENetPeer *peer) :
		m_mgmt(mgmt),
		m_peer(peer)
	{}

private:
	VServMgmt * m_mgmt;
	ENetPeer *  m_peer;
};

class VServUser
{
public:

	std::string m_name;
	std::string m_serv;
	uint16_t    m_id;

	long long m_time_stamp_last_recv;
};

class VServConExt
{
public:
	std::mutex m_mutex;
	std::map<Address, std::shared_ptr<VServUser>, address_less_t> m_addr_user_map;
	std::map<uint16_t, Address> m_uid_addr_map;

};

class VServWork
{

};

class VServMgmt
{
	typedef ::std::unique_ptr<ENetHost, void(*)(ENetHost *host)> unique_ptr_enethost;
	typedef ::std::unique_ptr<ENetEvent, void(*)(ENetEvent *evt)> unique_ptr_enetevent;

public:
	VServMgmt(size_t port) :
		m_addr { ENET_HOST_ANY, (uint16_t) port },
		m_host(enet_host_create(&m_addr, VSERV_MGMT_CLIENT_MAX, 1, 0, 0), deleteENetHost),
		m_thread()
	{
		if (! m_host)
			throw std::runtime_error("enet host create");
		m_thread.reset(new std::thread(&VServMgmt::funcThread, this));
	}

	void funcThread()
	{
		const size_t timeout_generation_max   = 4; /* [0,4] interval */
		uint32_t timeout_generation_vec[]     = { 1,  5,  10, 20,  500 };
		uint32_t timeout_generation_cnt_vec[] = { 10, 10, 10, 100, 0xFFFFFFFF };

		size_t timeout_generation     = 0;
		size_t timeout_generation_cnt = 0;

		int host_service_ret = 0;

		while (true) {
			unique_ptr_enetevent evt(createEmptyENetEvent(), deleteENetEvent);

			if (0 > (host_service_ret = enet_host_service(m_host.get(), evt.get(), timeout_generation_vec[timeout_generation])))
				throw std::runtime_error("enet host service");

			/* timeout - if too many, switch to next timeout generation */
			if (host_service_ret == 0) {
				if ((++timeout_generation_cnt % timeout_generation_cnt_vec[timeout_generation]) == 0)
					timeout_generation = MYMIN(timeout_generation + 1, timeout_generation_max);
				continue;
			}

			switch (evt->type)
			{

			case ENET_EVENT_TYPE_CONNECT:
			{
				Address addr = vserv_enetaddress_to_address(evt->peer->address);

				if (! (m_addr_peer_map.insert(std::make_pair(addr, evt->peer))).second)
					throw std::runtime_error("addr peer map insert");
			}
			break;

			case ENET_EVENT_TYPE_DISCONNECT:
			{
				Address addr = vserv_enetaddress_to_address(evt->peer->address);
				auto it = m_addr_peer_map.find(addr);
				assert(it != m_addr_peer_map.end());
				m_addr_peer_map.erase(it);
			}
			break;

			case ENET_EVENT_TYPE_RECEIVE:
			{
				Address addr = vserv_enetaddress_to_address(evt->peer->address);
				NetworkPacket packet(evt->packet->data, evt->packet->dataLength, networkpacket_buf_len_tag_t());
				VServRespondMgmt respond(this, evt->peer);

				virtualProcessPacket(&packet, &addr, &respond);
			}
			break;

			default:
				assert(0);

			}
		}
	}

	static ENetEvent * createEmptyENetEvent()
	{
		ENetEvent *evt = new ENetEvent();
		*evt = {};
		return evt;
	}

	static void deleteENetHost(ENetHost *host)
	{
		if (host)
			enet_host_destroy(host);
	}

	static void deleteENetEvent(ENetEvent *evt)
	{
		if (evt && evt->packet)
			enet_packet_destroy(evt->packet);
	}

	virtual void virtualProcessPacket(NetworkPacket *packet, Address *addr, VServRespond *respond) = 0;

private:
	ENetAddress  m_addr;
	unique_ptr_enethost m_host;
	std::unique_ptr<std::thread> m_thread;

	std::map<Address, ENetPeer *, address_less_t> m_addr_peer_map;
};

class VServMgmt0 : public VServMgmt
{
public:
	VServMgmt0(size_t port, const std::shared_ptr<VServConExt> &ext) :
		VServMgmt(port),
		m_ext(ext)
	{}

	void virtualProcessPacket(NetworkPacket *packet, Address *addr, VServRespond *respond) override
	{
		std::unique_lock<std::mutex> lock(m_ext->m_mutex);

		uint8_t id;
		
		(*packet) >> id;

		switch (id)
		{

		default:
			assert(0);
		}
	}

private:
	std::shared_ptr<VServConExt> m_ext;
};

class VServCtl
{
public:
	VServCtl(std::unique_ptr<VServMgmt> mgmt) :
		m_mgmt(std::move(mgmt))
	{}

private:
	std::unique_ptr<VServMgmt> m_mgmt;
};

void vserv_start_crank(size_t port)
{
	std::shared_ptr<VServConExt> ext(new VServConExt());
	std::unique_ptr<VServMgmt0> mgmt(new VServMgmt0(port, ext));
	std::unique_ptr<VServCtl> ctl(new VServCtl(std::move(mgmt)));
}

int main(int argc, char **argv)
{
	size_t fixmeport = 6757;

	vserv_start_crank(fixmeport);
	
	return EXIT_SUCCESS;
}

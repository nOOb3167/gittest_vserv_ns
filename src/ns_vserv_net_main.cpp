#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

// FIXME: #include <arpa/inet.h> for ntohl on NIX

#include <enet/enet.h>

#include <vserv/ns_vserv_net_main.h>
#include <vserv/ns_vserv_helpers.h>
#include <vserv/UDPSocket.h>

struct VServGroupAll
{
public:
	VServGroupAll() :
		m_id_vec(),
		m_sz_vec(),
		m_cache_id_group_map()
	{}

	VServGroupAll(std::vector<uint16_t> id_vec, std::vector<uint16_t> sz_vec) :
		m_id_vec(),
		m_sz_vec()
	{
		m_id_vec.swap(id_vec);
		m_sz_vec.swap(sz_vec);

		checkBasic();
		cacheRefresh();
	}

	void checkBasic()
	{
		std::set<uint16_t> uniq;
		size_t cnt = 0;

		for (size_t i = 0; i < m_id_vec.size(); i++)
			uniq.insert(m_id_vec[i]);

		for (size_t i = 0; i < m_sz_vec.size(); i++)
			cnt += m_sz_vec[i];

		if (m_id_vec.size() != uniq.size())
			throw std::runtime_error("groupall check uniq");
		if (m_id_vec.size() != cnt)
			throw std::runtime_error("groupall check szall");
	}

	void cacheRefresh()
	{
		m_cache_id_group_map.clear();

		uint16_t *p = m_id_vec.data();

		for (size_t i = 0; i < m_sz_vec.size(); i++) {
			if (p + m_sz_vec[i] > m_id_vec.data() + m_id_vec.size())
				throw std::runtime_error("groupall cache refresh");
			for (size_t j = 0; j < m_sz_vec[i]; j++)
				if (! m_cache_id_group_map.insert(std::make_pair(p[j], std::make_pair(p, m_sz_vec[i]))).second)
					throw std::runtime_error("groupall cache refresh");
			p += m_sz_vec[i];
		}
	}

private:
	std::vector<uint16_t> m_id_vec;
	std::vector<uint16_t> m_sz_vec;
	std::map<uint16_t, std::pair<uint16_t *, uint16_t> > m_cache_id_group_map;
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
	std::shared_ptr<VServGroupAll> m_groupall;
};

class VServWork
{

};

class VServMgmt0 : public VServMgmt
{
public:
	VServMgmt0(size_t port, const std::shared_ptr<VServConExt> &ext) :
		VServMgmt(port),
		m_ext(ext)
	{}

	void virtualProcessPacket(NetworkPacket *packet, VServRespond *respond, Address addr) override
	{
		GS_MACRO_VSERV_CMD_LIST_VAR(cmd_num_name);

		std::unique_lock<std::mutex> lock(m_ext->m_mutex);

		uint8_t id;
		
		(*packet) >> id;

		for (size_t i = 0; i < cmd_num_nameNum; i++)
			if (id == cmd_num_name[i].mNum)
				GS_DUMMY();

		switch (id)
		{

		case GS_VSERV_M_CMD_GROUPSET:
		{
			uint32_t id_num;
			uint32_t sz_num;

			(*packet) >> id_num >> sz_num;

			std::vector<uint16_t> id_vec(id_num);
			std::vector<uint16_t> sz_vec(sz_num);

			for (size_t i = 0; i < id_num; i++)
				(*packet) >> id_vec[i];
			for (size_t i = 0; i < sz_num; i++)
				(*packet) >> sz_vec[i];

			m_ext->m_groupall = std::shared_ptr<VServGroupAll>(new VServGroupAll(std::move(id_vec), std::move(sz_vec)));
		}
		break;

		case GS_VSERV_CMD_IDGET:
		{
			uint32_t generation;

			(*packet) >> generation;

			NetworkPacket packet_out(GS_VSERV_CMD_IDS, networkpacket_cmd_tag_t());

			// FIXME: implement generation properly (on ID source data structure)
			// FIXME: obtain ids from groupall or uid_addr_map ?

			packet_out << (generation + 1);
			packet_out << m_ext->m_uid_addr_map.size();

			for (auto it = m_ext->m_uid_addr_map.begin(); it != m_ext->m_uid_addr_map.end(); ++it)
				packet_out << it->first;

			respond->respondOneshot(std::move(packet_out), addr);
		}
		break;

		default:
			assert(0);
		}
	}

private:
	std::shared_ptr<VServConExt> m_ext;
};

NetworkPacket::NetworkPacket(uint8_t *data, size_t data_len, networkpacket_buf_len_tag_t) :
	m_data(data, data + data_len),
	m_off(0)
{
	m_data.reserve(VSERV_NETWORKPACKET_SIZE_INCREMENT);
}

NetworkPacket::NetworkPacket(uint8_t cmd, networkpacket_cmd_tag_t) :
	m_data(),
	m_off(0)
{
	(*this) << cmd;
}

uint8_t * NetworkPacket::getDataPtr()
{
	return m_data.data();
}

size_t NetworkPacket::getDataSize()
{
	assert(m_data.size() == m_off);
	return m_data.size();
}

inline uint8_t NetworkPacket::readU8(const uint8_t *data)
{
	return (m_data[0] << 0);
}

inline void NetworkPacket::writeU8(uint8_t *data, uint8_t i)
{
	data[0] = (i >> 0) & 0xFF;
}

inline uint16_t NetworkPacket::readU16(const uint8_t *data)
{
	return
		(data[0] << 8) | (data[1] << 0);
}

inline void NetworkPacket::writeU16(uint8_t *data, uint16_t i)
{
	data[0] = (i >> 8) & 0xFF;
	data[1] = (i >> 0) & 0xFF;
}

inline uint32_t NetworkPacket::readU32(const uint8_t *data)
{
	return
		(data[0] << 24) | (data[1] << 16) | (data[2] << 8) | (data[3] << 0);
}

inline void NetworkPacket::writeU32(uint8_t *data, uint32_t i)
{
	data[0] = (i >> 24) & 0xFF;
	data[1] = (i >> 16) & 0xFF;
	data[2] = (i >> 8) & 0xFF;
	data[3] = (i >> 0) & 0xFF;
}

inline void NetworkPacket::checkReadOffset(uint32_t from_offset, uint32_t field_size)
{
	if (from_offset + field_size > m_data.size())
		throw std::runtime_error("packet data size");
}

inline void NetworkPacket::checkDataSize(uint32_t field_size)
{
	if (m_off + field_size > m_data.capacity())
		m_data.reserve(m_data.capacity() + VSERV_NETWORKPACKET_SIZE_INCREMENT);
	if (m_off + field_size > m_data.size())
		m_data.resize(m_data.size() + field_size);
}

NetworkPacket& NetworkPacket::operator>>(uint8_t& dst)
{
	checkReadOffset(m_off, 1);
	dst = readU8(m_data.data() + m_off);
	m_off += 1;
	return *this;
}

NetworkPacket& NetworkPacket::operator<<(uint8_t src)
{
	checkDataSize(1);
	writeU8(m_data.data() + m_off, src);
	m_off += 1;
	return *this;
}

NetworkPacket& NetworkPacket::operator>>(uint16_t& dst)
{
	checkReadOffset(m_off, 2);
	dst = readU16(m_data.data() + m_off);
	m_off += 2;
	return *this;
}

NetworkPacket& NetworkPacket::operator<<(uint16_t src)
{
	checkDataSize(2);
	writeU16(m_data.data() + m_off, src);
	m_off += 2;
	return *this;
}

NetworkPacket& NetworkPacket::operator>>(uint32_t& dst)
{
	checkReadOffset(m_off, 4);
	dst = readU32(m_data.data() + m_off);
	m_off += 4;
	return *this;
}

NetworkPacket& NetworkPacket::operator<<(uint32_t src)
{
	checkDataSize(4);
	writeU32(m_data.data() + m_off, src);
	m_off += 4;
	return *this;
}

void VServRespond::respondOneshot(NetworkPacket packet, Address addr)
{
	virtualRespond(std::move(packet), &addr, 1);
}

VServRespondMgmt::VServRespondMgmt(VServMgmt *mgmt, ENetPeer *peer) :
	m_mgmt(mgmt),
	m_peer(peer)
{}

void VServRespondMgmt::deleteENetPacket(ENetPacket *pkt)
{
	if (pkt)
		enet_packet_destroy(pkt);
}

void VServRespondMgmt::virtualRespond(NetworkPacket packet, Address *addr_vec, size_t addr_num)
{
	/* enet_peer_send takes ownership of the packet on success (enet_packet_destroy MUST NOT be called).
	   enet_peer_send does not take ownership of the packet on failure (enet_packet_destroy MUST be called).
	   in the case multiple enet_peer_send (completing with succeess) calls are issued for the same packet
	   the first call will take ownership.
	     due to above behaviour of enet_packet_send, ownership of packet
	     is release()d, avoiding enet_packet_destroy after success of a enet_peer_send
	*/
	/* ENET_PACKET_FLAG_NO_ALLOCATE is NOT used by vserv_ns design */

	unique_ptr_enetpacket pkt(enet_packet_create(packet.getDataPtr(), packet.getDataSize(), ENET_PACKET_FLAG_RELIABLE), deleteENetPacket);
	ENetPacket * pkt_dummy = pkt.get();

	if (! pkt)
		throw std::runtime_error("respond mgmt packet");

	for (size_t write_num = 0; write_num < addr_num; write_num++) {
		auto itPeer = m_mgmt->getAddrPeerMap().find(addr_vec[write_num]);
		if (itPeer == m_mgmt->getAddrPeerMap().end())
			throw std::runtime_error("respond mgmt peer find");
		if (!!enet_peer_send(itPeer->second, 0, pkt_dummy))
			throw std::runtime_error("respond mgmt peer send");
		pkt.release();
	}
}

VServMgmt::VServMgmt(size_t port) :
	m_addr{ ENET_HOST_ANY, (uint16_t)port },
	m_host(enet_host_create(&m_addr, VSERV_MGMT_CLIENT_MAX, 1, 0, 0), deleteENetHost),
	m_thread()
{
	if (!m_host)
		throw std::runtime_error("enet host create");
	m_thread.reset(new std::thread(&VServMgmt::funcThread, this));
}

std::map<Address, ENetPeer *, address_less_t> & VServMgmt::getAddrPeerMap()
{
	return m_addr_peer_map;
}

void VServMgmt::funcThread()
{
	const size_t timeout_generation_max = 4; /* [0,4] interval */
	uint32_t timeout_generation_vec[] = { 1,  5,  10, 20,  500 };
	uint32_t timeout_generation_cnt_vec[] = { 10, 10, 10, 100, 0xFFFFFFFF };

	size_t timeout_generation = 0;
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

			if (!(m_addr_peer_map.insert(std::make_pair(addr, evt->peer))).second)
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

			virtualProcessPacket(&packet, &respond, addr);
		}
		break;

		default:
			assert(0);

		}
	}
}

ENetEvent * VServMgmt::createEmptyENetEvent()
{
	ENetEvent *evt = new ENetEvent();
	*evt = {};
	return evt;
}

void VServMgmt::deleteENetHost(ENetHost *host)
{
	if (host)
		enet_host_destroy(host);
}

void VServMgmt::deleteENetEvent(ENetEvent *evt)
{
	if (evt && evt->packet)
		enet_packet_destroy(evt->packet);
}

VServCtl::VServCtl(std::unique_ptr<VServMgmt> mgmt) :
	m_mgmt(std::move(mgmt))
{}

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

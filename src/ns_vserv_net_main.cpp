#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <exception>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <time.h>
#include <enet/enet.h>

#include <vserv/ns_vserv_net_main.h>
#include <vserv/ns_vserv_helpers.h>
#include <vserv/UDPSocket.h>

int g_vserv_timeout_check_disable = 0;

long long vserv_timestamp()
{
	struct timespec tspec = {};

#ifdef _WIN32
	/* supposedly not available in VS2013 - switch to something else */
	if (! timespec_get(&tspec, TIME_UTC))
		throw std::runtime_error("timestamp get");
#else
	if (!! clock_gettime(CLOCK_MONOTONIC, &tspec))
		throw std::runtime_error("timestamp get");
#endif
	return (tspec.tv_sec * 1000) + (tspec.tv_nsec / (1000 * 1000));
}

struct ManagedIdPtrData
{
	ManagedIdPtrData(std::function<void(uint16_t)> delete_id, uint16_t id) :
		m_delete_id(delete_id),
		m_id(id)
	{}

	~ManagedIdPtrData()
	{
		m_delete_id(m_id);
	}

	std::function<void(uint16_t)> m_delete_id;
	uint16_t m_id;
};

typedef ::std::unique_ptr<ManagedIdPtrData> unique_ptr_userid;

class VServManageId : public std::enable_shared_from_this<VServManageId>
{
public:
	static std::shared_ptr<VServManageId> create()
	{
		return std::shared_ptr<VServManageId>(new VServManageId());
	}

protected:
	VServManageId() :
		m_taken_set(),
		m_counter(0),
		m_max_id(0xFFFE)  // 0xFFFF reserved for invalid id
	{}

public:
	unique_ptr_userid genId()
	{
		uint16_t counter = m_counter % m_max_id;
		size_t retry_limit = m_max_id;

		while (m_taken_set.find(counter) != m_taken_set.end()) {
			counter = (counter + 1) % m_max_id;
			if (retry_limit-- == 0)
				throw std::runtime_error("out of ids");
		}

		m_taken_set.insert(counter);
		m_counter = counter;

		return std::move(unique_ptr_userid(new ManagedIdPtrData(std::bind(s_delId, shared_from_this(), std::placeholders::_1), counter)));
	}

	void delId(uint16_t id)
	{
		m_taken_set.erase(id);
	}

	static void s_delId(const std::shared_ptr<VServManageId> &manageid, uint16_t id)
	{
		manageid->delId(id);
	}

private:
	std::set<uint16_t> m_taken_set;
	size_t m_counter;
	size_t m_max_id;
};

class VServGroupAll
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

	/** returned pointer / vec ownership does not transfer to caller
	    use of returned data must cease before caller allows VServGroupAll to be destroyed */
	void lookupGroupFor(uint16_t id, uint16_t **out_id_vec, size_t *out_id_num)
	{
		auto it = m_cache_id_group_map.find(id);

		if (it == m_cache_id_group_map.end()) {
			*out_id_vec = NULL;
			*out_id_num = 0;
		}
		else {
			*out_id_vec = it->second.first;
			*out_id_num = it->second.second;
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
	VServUser(std::string name, std::string serv, const std::shared_ptr<VServManageId> &manageid) :
		m_name(std::move(name)),
		m_serv(std::move(serv)),
		m_id(std::move(manageid->genId())),
		m_timestamp_last_recv(0)
	{}

	std::string m_name;
	std::string m_serv;
	unique_ptr_userid m_id;

	long long m_timestamp_last_recv;
};

class VServConExt
{
public:
	VServConExt() :
		m_mutex(),
		m_manageid(VServManageId::create()),
		m_addr_user_map(),
		m_uid_addr_map(),
		m_groupall(new VServGroupAll()),
		m_timestamp_last_user_timeout_check(0)
	{}

	std::mutex m_mutex;
	std::shared_ptr<VServManageId> m_manageid;
	std::map<Address, std::shared_ptr<VServUser>, address_less_t> m_addr_user_map;
	std::map<uint16_t, Address> m_uid_addr_map;
	std::shared_ptr<VServGroupAll> m_groupall;
	long long m_timestamp_last_user_timeout_check;
};

class VServWork0 : public VServWork
{
public:
	VServWork0(size_t port, const std::shared_ptr<VServConExt> &ext) :
		VServWork(port),
		m_ext(ext)
	{}

	void virtualProcessPacket(NetworkPacket *packet, VServRespond *respond, Address addr) override
	{
		GS_MACRO_VSERV_CMD_LIST_VAR(cmd_num_name);

		std::unique_lock<std::mutex> lock(m_ext->m_mutex);

		long long timestamp = vserv_timestamp();

		uint8_t id;

		(*packet) >> id;

		for (size_t i = 0; i < cmd_num_nameNum; i++)
			if (id == cmd_num_name[i].mNum)
				GS_DUMMY();

		std::shared_ptr<VServUser> user = identifyProcess(packet, respond, addr);

		bool haveAnyTimeout = timeoutRecv(timestamp, user.get());

		switch (id)
		{

		case GS_VSERV_CMD_IDENT:
		{
			/* intention is to have already had a go at parsing this message
			   during prior identification. therefore just passthrough. */
		}
		break;

		case GS_VSERV_CMD_NAMEGET:
		{
			NetworkPacket packet_out(GS_VSERV_CMD_NAMES, networkpacket_cmd_tag_t());

			assert(packet->getRemainingSize() % 2 == 0);
			size_t idnum = packet->getRemainingSize() / 2;

			for (size_t i = 0; i < idnum; i++) {
				uint16_t id;
				(*packet) >> id;
				auto it = m_ext->m_uid_addr_map.find(id);
				if (it == m_ext->m_uid_addr_map.end())
					continue;
				auto it2 = m_ext->m_addr_user_map.find(it->second);
				if (it2 == m_ext->m_addr_user_map.end())
					continue;
				const VServUser &user = *it2->second;
				packet_out << user.m_id->m_id << user.m_name.size();
				packet_out.outSizedStr(user.m_name.data(), user.m_name.size());
			}

			respond->respondOneshot(std::move(packet_out), addr);
		}
		break;

		case GS_VSERV_CMD_BROADCAST:
		{
			std::vector<Address> addr_vec;
			for (auto it = m_ext->m_addr_user_map.begin(); it != m_ext->m_addr_user_map.end(); ++it)
				addr_vec.push_back(it->first);
			respond->respondMulti(std::move(*packet), addr_vec.data(), addr_vec.size());
		}
		break;

		case GS_VSERV_CMD_GROUP_MODE_MSG:
		{
			std::shared_ptr<VServGroupAll> groupall = m_ext->m_groupall;

			uint8_t  mode = 0;
			uint16_t id  = 0;
			uint16_t blk = 0;
			uint16_t seq = 0;

			(*packet) >> mode >> id >> blk >> seq;

			NetworkPacket packet_out = std::move(*packet);

			/* allow client to send the packet with 'id' field value GS_VSERV_USER_ID_SERVFILL.
			   upon receiving such 'id', substitute it with the client's actual id. */

			if (id == GS_VSERV_USER_ID_SERVFILL) {
				packet_out.rewriteU16At(1 /*cmd*/ + 1 /*mode*/, user->m_id->m_id, &id);
				id = user->m_id->m_id;
			}

			/* the value of 'id' field is not really a choice anyway.
			   it must be the client's actual id. either apriori(sic) or after the above fixup. */

			if (id != user->m_id->m_id)
				throw ProtocolExc("user id mismatch");

			switch (mode)
			{

			case GS_VSERV_GROUP_MODE_NONE:
			{
			}
			break;

			case GS_VSERV_GROUP_MODE_S:
			{
				uint16_t *id_vec = NULL;
				size_t id_num = 0;
				uint16_t dummyid = 0;
				m_ext->m_groupall->lookupGroupFor(id, &id_vec, &id_num);
				if (! id_vec) {
					static unsigned int Cnt = 0;
					if (! (Cnt++ % 250))
						GS_DUMMY(I, PF, "ungrouped [id=%d]", (int)Id);
					// FIXME: for testing purposes, ungrouped just routes to id0
					id_vec = &dummyid;
					id_num = 1;
				}
				respond->respondMultiId(std::move(packet_out), id_vec, id_num, m_ext->m_uid_addr_map);
			}
			break;

			case GS_VSERV_CMD_PING:
			{
				/* currently no processing */
			}
			break;

			default:
				throw ProtocolExc("unknown mode");
			}

		}
		break;

		default:
			throw ProtocolExc("unrecognized command");
		}

		if (haveAnyTimeout)
			timeoutDisconnect(timestamp);
	}

	std::shared_ptr<VServUser> identifyProcess(NetworkPacket *packet, VServRespond *respond, Address addr)
	{
		auto it = m_ext->m_addr_user_map.find(addr);

		/* return existing */
		if (it != m_ext->m_addr_user_map.end())
			return it->second;

		/* missing - must be ident. create new. */
		uint32_t user_rand = 0;
		std::shared_ptr<VServUser> new_user = identifyParseIdent(packet, &user_rand);
		/* acknowledge new */
		NetworkPacket packet_out(GS_VSERV_CMD_IDENT_ACK, networkpacket_cmd_tag_t());
		packet_out << user_rand << new_user->m_id->m_id;
		respond->respondOneshot(std::move(packet_out), addr);
		/* insert new */
		if (! m_ext->m_uid_addr_map.insert(std::make_pair(new_user->m_id->m_id, addr)).second)
			throw std::runtime_error("uid addr map insert");
		if (! m_ext->m_addr_user_map.insert(std::make_pair(addr, new_user)).second)
			throw std::runtime_error("addr user map insert");

		return new_user;
	}

	std::shared_ptr<VServUser> identifyParseIdent(NetworkPacket *packet, uint32_t *o_user_rand)
	{
		std::shared_ptr<VServUser> new_user;

		uint8_t  cmd;
		uint32_t user_rand;
		uint32_t name_len;
		uint32_t serv_len;

		(*packet) >> cmd >> user_rand >> name_len >> serv_len;

		if (cmd != GS_VSERV_CMD_IDENT)
			throw ProtocolExc("not cmd ident");

		std::string name(packet->inSizedStr(name_len), name_len);
		std::string serv(packet->inSizedStr(serv_len), serv_len);

		return std::shared_ptr<VServUser>(new VServUser(std::move(name), std::move(serv), m_ext->m_manageid));
	}

	bool timeoutRecv(long long timestamp, VServUser *user_recv)
	{
		user_recv->m_timestamp_last_recv = timestamp;

		if (g_vserv_timeout_check_disable)
			return false;

		if (timestamp < m_ext->m_timestamp_last_user_timeout_check + VSERV_USER_TIMEOUT_CHECK_MS)
			return false;

		for (auto it = m_ext->m_addr_user_map.begin(); it != m_ext->m_addr_user_map.end(); ++it) {
			if (timestamp < it->second->m_timestamp_last_recv + VSERV_USER_TIMEOUT_MS)
				continue;
			/* timed out */
			return true;
		}

		return false;
	}

	void timeoutDisconnect(long long timestamp)
	{
		for (auto it = m_ext->m_addr_user_map.begin(); it != m_ext->m_addr_user_map.end(); ++it) {
			if (timestamp < it->second->m_timestamp_last_recv + VSERV_USER_TIMEOUT_MS) {
				++it;
			}
			else {
				/* timed out */
				m_ext->m_uid_addr_map.erase(it->second->m_id->m_id);
				it = m_ext->m_addr_user_map.erase(it);
			}
		}
	}

private:
	std::shared_ptr<VServConExt> m_ext;
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

ProtocolExc::ProtocolExc(const char *msg) :
	std::runtime_error(msg)
{}

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
	return m_data.size();
}

size_t NetworkPacket::getRemainingSize()
{
	assert(m_data.size() >= m_off);
	return m_data.size() - m_off;
}

const char * NetworkPacket::inSizedStr(size_t len)
{
	checkReadOffset(m_off, len);
	const char *p = (const char *)(m_data.data() + m_off);
	m_off += len;
	return p;
}

void NetworkPacket::outSizedStr(const char *str, size_t len)
{
	checkDataSize(len);
	memcpy(m_data.data() + m_off, str, len);
	m_off += len;
}

void NetworkPacket::rewriteU16At(size_t off, uint16_t i, uint16_t *opt_old_val)
{
	if (getDataSize() < off + 2)
		throw std::runtime_error("packet data size at");
	if (opt_old_val)
		assert(*opt_old_val == ((m_data[off + 0] << 8) | (m_data[off + 1] << 0)));
	m_data[off + 0] = (i >> 8) & 0xFF;
	m_data[off + 1] = (i >> 0) & 0xFF;
}

uint8_t NetworkPacket::readU8(const uint8_t *data)
{
	return (m_data[0] << 0);
}

void NetworkPacket::writeU8(uint8_t *data, uint8_t i)
{
	data[0] = (i >> 0) & 0xFF;
}

uint16_t NetworkPacket::readU16(const uint8_t *data)
{
	return
		(data[0] << 8) | (data[1] << 0);
}

void NetworkPacket::writeU16(uint8_t *data, uint16_t i)
{
	data[0] = (i >> 8) & 0xFF;
	data[1] = (i >> 0) & 0xFF;
}

uint32_t NetworkPacket::readU32(const uint8_t *data)
{
	return
		(data[0] << 24) | (data[1] << 16) | (data[2] << 8) | (data[3] << 0);
}

void NetworkPacket::writeU32(uint8_t *data, uint32_t i)
{
	data[0] = (i >> 24) & 0xFF;
	data[1] = (i >> 16) & 0xFF;
	data[2] = (i >> 8) & 0xFF;
	data[3] = (i >> 0) & 0xFF;
}

void NetworkPacket::checkReadOffset(uint32_t from_offset, uint32_t field_size)
{
	if (from_offset + field_size > m_data.size())
		throw std::runtime_error("packet data size");
}

void NetworkPacket::checkDataSize(uint32_t field_size)
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

void VServRespond::respondMulti(NetworkPacket packet, Address *addr_vec, size_t addr_num)
{
	virtualRespond(std::move(packet), addr_vec, addr_num);
}

void VServRespond::respondMultiId(NetworkPacket packet, uint16_t *id_vec, size_t id_num, const std::map<uint16_t, Address> &uid_addr_map)
{
	/* comfy obfuscated C code with C++ constructs */
	assert(id_num <= VSERV_BOTH_CLIENT_CEIL);
	uint8_t hax[sizeof (Address) * VSERV_BOTH_CLIENT_CEIL];
	size_t  hax_num = 0;
	std::exception_ptr exc;
	try {
		for (size_t i = 0; i < id_num; i++) {
			auto it = uid_addr_map.find(id_vec[i]);
			if (it == uid_addr_map.end())
				continue;
			new (((Address *)hax) + hax_num) Address(it->second);
			hax_num++;
		}

		virtualRespond(std::move(packet), (Address *)hax, hax_num);
	}
	catch (const std::exception &) {
		exc = std::current_exception();
	}
	
	for (size_t i = 0; i < hax_num; i++)
		(((Address *)hax) + hax_num)->~Address();

	if (exc)
		std::rethrow_exception(exc);
}

VServRespondMgmt::VServRespondMgmt(const std::shared_ptr<std::map<Address, ENetPeer *, address_less_t> > &addr_peer_map) :
	m_addr_peer_map(addr_peer_map)
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
		auto itPeer = m_addr_peer_map->find(addr_vec[write_num]);
		if (itPeer == m_addr_peer_map->end())
			throw std::runtime_error("respond mgmt peer find");
		if (!!enet_peer_send(itPeer->second, 0, pkt_dummy))
			throw std::runtime_error("respond mgmt peer send");
		pkt.release();
	}
}

VServWork::Write::Write(NetworkPacket packet, Address *addr_vec, size_t addr_num) :
	m_packet(std::move(packet)),
	m_addr(),
	m_addr_num(addr_num),
	m_addr_idx(0)
{
	assert(addr_num <= m_addr.size());
	std::copy(addr_vec, addr_vec + addr_num, m_addr.begin());
}

VServWork::VServWork(size_t port) :
	m_addr(AF_INET, (uint16_t)port, 0, address_ipv4_tag_t()),
	m_sock(new UDPSocket()),
	m_thread(),
	m_writequeue(new std::deque<VServWork::Write>())
{
	m_sock->Bind(m_addr);
	m_thread.reset(new std::thread(&VServWork::funcThread, this));
}

void VServWork::funcThread()
{
	const size_t timeout_generation_max = 4; /* [0,4] interval */
	uint32_t timeout_generation_vec[] = { 1,  5,  10, 20,  500 };
	uint32_t timeout_generation_cnt_vec[] = { 10, 10, 10, 100, 0xFFFFFFFF };

	size_t timeout_generation = 0;
	size_t timeout_generation_cnt = 0;

	while (true) {
		Address addr;
		uint8_t data[VSERV_UDPSIZE_MAX] = {};

		while (!m_writequeue->empty()) {
			Write & write = m_writequeue->front();
			size_t i = write.m_addr_idx;
			for (/*dummy*/; i < write.m_addr_num; i++)
				m_sock->Send(write.m_addr[i], write.m_packet.getDataPtr(), write.m_packet.getDataSize());
			if (i == write.m_addr_num)
				m_writequeue->pop_front();
		}

		int rcvt = m_sock->ReceiveWaiting(&addr, data, VSERV_UDPSIZE_MAX, timeout_generation_vec[timeout_generation]);

		/* timeout - if too many, switch to next timeout generation */
		if (rcvt == -1) {
			if ((++timeout_generation_cnt % timeout_generation_cnt_vec[timeout_generation]) == 0)
				timeout_generation = MYMIN(timeout_generation + 1, timeout_generation_max);
			continue;
		}

		NetworkPacket packet(data, rcvt, networkpacket_buf_len_tag_t());
		VServRespondWork respond(m_writequeue);

		virtualProcessPacket(&packet, &respond, addr);
	}
}

VServRespondWork::VServRespondWork(const std::shared_ptr<std::deque<VServWork::Write> > & writequeue) :
	m_writequeue(writequeue)
{}

void VServRespondWork::virtualRespond(NetworkPacket packet, Address *addr_vec, size_t addr_num)
{
	m_writequeue->push_back(VServWork::Write(std::move(packet), addr_vec, addr_num));
}

VServMgmt::VServMgmt(size_t port) :
	m_addr{ ENET_HOST_ANY, (uint16_t)port },
	m_host(enet_host_create(&m_addr, VSERV_MGMT_CLIENT_MAX, 1, 0, 0), deleteENetHost),
	m_thread(),
	m_addr_peer_map(new std::map<Address, ENetPeer *, address_less_t>())
{
	if (!m_host)
		throw std::runtime_error("enet host create");
	m_thread.reset(new std::thread(&VServMgmt::funcThread, this));
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

			if (!(m_addr_peer_map->insert(std::make_pair(addr, evt->peer))).second)
				throw std::runtime_error("addr peer map insert");
		}
		break;

		case ENET_EVENT_TYPE_DISCONNECT:
		{
			Address addr = vserv_enetaddress_to_address(evt->peer->address);
			auto it = m_addr_peer_map->find(addr);
			assert(it != m_addr_peer_map->end());
			m_addr_peer_map->erase(it);
		}
		break;

		case ENET_EVENT_TYPE_RECEIVE:
		{
			Address addr = vserv_enetaddress_to_address(evt->peer->address);
			NetworkPacket packet(evt->packet->data, evt->packet->dataLength, networkpacket_buf_len_tag_t());
			VServRespondMgmt respond(m_addr_peer_map);

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

VServCtl::VServCtl(std::unique_ptr<VServWork> work, std::unique_ptr<VServMgmt> mgmt) :
	m_work(std::move(work)),
	m_mgmt(std::move(mgmt))
{}

void vserv_start_crank(size_t port_work, size_t port_mgmt)
{
	std::shared_ptr<VServConExt> ext(new VServConExt());
	std::unique_ptr<VServWork0> work(new VServWork0(port_work, ext));
	std::unique_ptr<VServMgmt0> mgmt(new VServMgmt0(port_mgmt, ext));
	std::unique_ptr<VServCtl> ctl(new VServCtl(std::move(work), std::move(mgmt)));
}

int main(int argc, char **argv)
{
	size_t fixmeportwork = 3757;
	size_t fixmeportmgmt = 3758;

	if (!! enet_initialize())
		throw std::runtime_error("enet initialize");

	vserv_start_crank(fixmeportwork, fixmeportmgmt);
	
	return EXIT_SUCCESS;
}

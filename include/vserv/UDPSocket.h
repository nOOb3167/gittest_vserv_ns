#ifndef _UDPSOCKET_H_
#define _UDPSOCKET_H_

#include <cstdint>
#include <cstring>
#include <memory>
#include <stdexcept>

#include <enet/enet.h>  // FIXME: including enet just for the WIN/NIX socket definitions

#define VSERV_ADDRESS_ADDR_SIZE 16

struct address_ipv4_tag_t {};

class Address
{
public:
	Address() :
		m_family(AF_UNSPEC),
		m_port(0),
		m_addr()
	{
		memset(m_addr, '\0', VSERV_ADDRESS_ADDR_SIZE);
	}


	Address(int family, uint16_t port, uint32_t addr, address_ipv4_tag_t) :
		m_family(family),
		m_port(port),
		m_addr()
	{
		memset(m_addr, '\0', VSERV_ADDRESS_ADDR_SIZE);
		memcpy(m_addr, &addr, sizeof (uint32_t));
	}

	int getFamily() { return m_family; }
	uint16_t getPort() { return m_port; }
	uint32_t getAddr4() { return *(uint32_t *) m_addr; }

private:
	int      m_family;
	uint16_t m_port;
	uint8_t  m_addr[VSERV_ADDRESS_ADDR_SIZE];

	friend struct address_less_t;
};

struct address_less_t {
	bool operator()(const Address &a, const Address &b) const
	{
		bool n0 = a.m_family < b.m_family;
		bool n1 = a.m_port < b.m_port;
		int  n2cmp = memcmp(a.m_addr, b.m_addr, VSERV_ADDRESS_ADDR_SIZE);
		bool n2 = n2cmp < 0;
		return a.m_family != b.m_family ? n0 : (a.m_port != b.m_port ? n1 : (n2cmp != 0 ? n2 : false));
	}
};

Address vserv_enetaddress_to_address(ENetAddress enet_addr)
{
	return Address(AF_INET, enet_addr.port, ntohl(enet_addr.host), address_ipv4_tag_t());
}

class UDPSocket
{
	typedef ::std::unique_ptr<int, void(*)(int *fd)> unique_ptr_fd;

public:
	UDPSocket() :
		m_handle(new int(socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)), deleteFd)
	{
		if (*m_handle < 0)
			throw std::runtime_error("UDPSocket socket");
	}

	void Bind(Address addr)
	{
		if (addr.getFamily() != AF_INET)
			throw std::runtime_error("UDPSocket bind family");

		struct sockaddr_in sockaddr = {};

		sockaddr.sin_family = addr.getFamily();
		sockaddr.sin_port = htons(addr.getPort());
		sockaddr.sin_addr.s_addr = htonl(addr.getAddr4());

		if (bind(*m_handle, (struct sockaddr *) &sockaddr, sizeof sockaddr) < 0)
			throw std::runtime_error("UDPSocket bind bind");
	}

	void Send(Address dest, const void *data, size_t size)
	{
		if (dest.getFamily() != AF_INET)
			throw std::runtime_error("UDPSocket send family");

		struct sockaddr_in sockaddr = {};

		sockaddr.sin_family = dest.getFamily();
		sockaddr.sin_port = htons(dest.getPort());
		sockaddr.sin_addr.s_addr = htonl(dest.getAddr4());

		int sent = sendto(*m_handle, (const char *)data, size, 0, (struct sockaddr *) &sockaddr, sizeof sockaddr);

		if (sent < 0 || sent != size)
			throw std::runtime_error("UDPSocket send sent");
	}

	int ReceiveWaiting(Address *sender, void *data, int size, int timeout_ms)
	{
		if (! WaitData(timeout_ms))
			return -1;

		struct sockaddr_in sockaddr = {};
		int sockaddr_len = sizeof sockaddr;

		int rcvt = recvfrom(*m_handle, (char *) data, size, 0, (struct sockaddr *) &sockaddr, &sockaddr_len);

		if (rcvt < 0 || sockaddr.sin_family != AF_INET)
			throw std::runtime_error("UDPSocket send sent");

		int family = sockaddr.sin_family;
		uint16_t port = ntohs(sockaddr.sin_port);
		uint32_t addr = ntohl(sockaddr.sin_addr.s_addr);

		*sender = Address(family, port, addr, address_ipv4_tag_t());

		return rcvt;
	}

	bool WaitData(int timeout_ms)
	{
		fd_set readset;

		FD_ZERO(&readset);
		FD_SET(*m_handle, &readset);

		struct timeval tv = {};
		tv.tv_sec  = 0;
		tv.tv_usec = timeout_ms * 1000;

		int result = select(*m_handle + 1, &readset, NULL, NULL, &tv);

		if (result < 0)
			throw std::runtime_error("UDPSocket wait");

		if (result == 0 || ! FD_ISSET(*m_handle, &readset))
			return false;

		return true;
	}

	static void deleteFd(int *fd)
	{
		if (fd) {
			if (*fd != -1) {
#ifdef _WIN32
				closesocket(*fd);
#else
				close(*fd);
#endif
			}

			*fd = -1;
		}
	}

private:
	unique_ptr_fd m_handle;
};

#endif /* _UDPSOCKET_H_ */

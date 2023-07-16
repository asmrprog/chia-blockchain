from __future__ import annotations

import asyncio
import ipaddress
import logging
import signal
import traceback
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, List, Optional

import aiosqlite
from dnslib import AAAA, NS, QTYPE, RR, SOA, A, DNSError, DNSHeader, DNSRecord

from chia.seeder.crawl_store import CrawlStore
from chia.util.chia_logging import initialize_logging
from chia.util.config import load_config
from chia.util.default_root import DEFAULT_ROOT_PATH
from chia.util.path import path_from_root

SERVICE_NAME = "seeder"
log = logging.getLogger(__name__)


# DNS snippet taken from: https://gist.github.com/pklaus/b5a7876d4d2cf7271873


class DomainName(str):
    def __getattr__(self, item: str) -> DomainName:
        return DomainName(item + "." + self)  # DomainName.NS becomes DomainName("NS.DomainName")


IP = "127.0.0.1"  # this is a placeholder for NS and SOA records


class EchoServerProtocol(asyncio.DatagramProtocol):
    transport: asyncio.DatagramTransport
    data_queue: asyncio.Queue[tuple[DNSRecord, tuple[str, int]]]
    callback: Callable[[DNSRecord], Awaitable[Optional[DNSRecord]]]

    def __init__(self, callback: Callable[[DNSRecord], Awaitable[Optional[DNSRecord]]]) -> None:
        self.data_queue = asyncio.Queue()
        self.callback = callback
        asyncio.ensure_future(self.respond())

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        # we use the #ignore because transport is a subclass of BaseTransport, but we need the real type.
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            dns_request: DNSRecord = DNSRecord.parse(data)  # it's better to parse here, so we have a real type.
        except DNSError as e:
            log.warning(f"Received invalid DNS request: {e}")
            return
        except Exception as e:
            log.error(f"Exception when receiving a datagram: {e}. Traceback: {traceback.format_exc()}.")
            return
        asyncio.ensure_future(self.handler(dns_request, addr))

    async def respond(self) -> None:
        while True:
            try:
                reply, caller = await self.data_queue.get()
                self.transport.sendto(reply.pack(), caller)
            except Exception as e:
                log.error(f"Exception: {e}. Traceback: {traceback.format_exc()}.")

    async def handler(self, data: DNSRecord, caller: tuple[str, int]) -> None:
        try:
            data = await self.callback(data)
            if data is None:
                return
            await self.data_queue.put((data, caller))
        except Exception as e:
            log.error(f"Exception during DNS record processing: {e}. Traceback: {traceback.format_exc()}.")


@dataclass
class DNSServer:
    config: Dict[str, Any]
    root_path: Path
    lock: asyncio.Lock = asyncio.Lock()
    shutdown_event: asyncio.Event = asyncio.Event()
    db_connection: aiosqlite.Connection = field(init=False)
    crawl_store: CrawlStore = field(init=False)
    reliable_task: asyncio.Task[None] = field(init=False)
    transport: asyncio.DatagramTransport = field(init=False)
    protocol: EchoServerProtocol = field(init=False)
    dns_port: int = field(init=False)
    db_path: Path = field(init=False)
    domain: DomainName = field(init=False)
    ns1: DomainName = field(init=False)
    ns2: Optional[DomainName] = field(init=False)
    ns_records: List[RR] = field(init=False)
    ttl: int = field(init=False)
    soa_record: RR = field(init=False)
    reliable_peers_v4: List[str] = field(default_factory=list)
    reliable_peers_v6: List[str] = field(default_factory=list)
    pointer_v4: int = 0
    pointer_v6: int = 0

    def __post_init__(self) -> None:
        """
        We initialize all the variables set to field(init=False) here.
        """
        # From Config
        self.dns_port: int = self.config.get("dns_port", 53)
        # DB Path
        crawler_db_path: str = self.config.get("crawler_db_path", "crawler.db")
        self.db_path: Path = path_from_root(self.root_path, crawler_db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        # DNS info
        self.domain: DomainName = DomainName(self.config["domain_name"])
        self.ns1: DomainName = DomainName(self.config["nameserver"])
        self.ns2: Optional[DomainName] = (
            DomainName(self.config["nameserver2"]) if self.config.get("nameserver2") else None
        )
        self.ns_records: List[NS] = [NS(self.ns1), NS(self.ns2)] if self.ns2 else [NS(self.ns1)]
        self.ttl: int = self.config["ttl"]
        self.soa_record: SOA = SOA(
            mname=self.ns1,  # primary name server
            rname=self.config["soa"]["rname"],  # email of the domain administrator
            times=(
                self.config["soa"]["serial_number"],
                self.config["soa"]["refresh"],
                self.config["soa"]["retry"],
                self.config["soa"]["expire"],
                self.config["soa"]["minimum"],
            ),
        )

    @asynccontextmanager
    async def run(self) -> AsyncIterator[None]:
        await self.setup_signal_handlers()
        self.db_connection = await aiosqlite.connect(self.db_path, timeout=60)
        self.crawl_store = CrawlStore(self.db_connection)
        # Get a reference to the event loop as we plan to use
        # low-level APIs.
        loop = asyncio.get_running_loop()

        # One protocol instance will be created to serve all
        # client requests.
        self.transport, self.protocol = await loop.create_datagram_endpoint(
            lambda: EchoServerProtocol(self.dns_response), local_addr=("::0", self.dns_port)
        )
        self.reliable_task = asyncio.create_task(self.periodically_get_reliable_peers())
        try:
            yield
        finally:  # catches any errors and properly shuts down the server
            if not self.shutdown_event.is_set():
                await self.stop()

    async def setup_signal_handlers(self) -> None:
        loop = asyncio.get_running_loop()
        try:
            loop.add_signal_handler(signal.SIGINT, self._accept_signal)
            loop.add_signal_handler(signal.SIGTERM, self._accept_signal)
        except NotImplementedError:
            log.info("signal handlers unsupported on this platform")

    def _accept_signal(self) -> None:
        asyncio.create_task(self.stop())

    async def stop(self) -> None:
        self.reliable_task.cancel()  # cancel the task
        await self.db_connection.close()
        self.transport.close()
        self.shutdown_event.set()

    async def periodically_get_reliable_peers(self) -> None:
        sleep_interval = 0
        while not self.shutdown_event.is_set():
            try:
                new_reliable_peers = await self.crawl_store.get_good_peers()
                async with self.lock:
                    self.reliable_peers_v4 = []
                    self.reliable_peers_v6 = []
                    for peer in new_reliable_peers:
                        ipv4 = True
                        try:
                            _ = ipaddress.IPv4Address(peer)
                        except ValueError:
                            ipv4 = False
                        if ipv4:
                            self.reliable_peers_v4.append(peer)
                        else:
                            try:
                                _ = ipaddress.IPv6Address(peer)
                            except ValueError:
                                continue
                            self.reliable_peers_v6.append(peer)
                    self.pointer_v4 = 0
                    self.pointer_v6 = 0
                log.error(
                    f"Number of reliable peers discovered in dns server:"
                    f" IPv4 count - {len(self.reliable_peers_v4)}"
                    f" IPv6 count - {len(self.reliable_peers_v6)}"
                )
            except Exception as e:
                log.error(f"Exception: {e}. Traceback: {traceback.format_exc()}.")

            sleep_interval = min(15, sleep_interval + 1)
            await asyncio.sleep(sleep_interval * 60)

    async def get_peers_to_respond(self, ipv4_count: int, ipv6_count: int) -> List[str]:
        peers = []
        async with self.lock:
            # Append IPv4.
            size = len(self.reliable_peers_v4)
            if ipv4_count > 0 and size <= ipv4_count:
                peers = self.reliable_peers_v4
            elif ipv4_count > 0:
                peers = [self.reliable_peers_v4[i % size] for i in range(self.pointer_v4, self.pointer_v4 + ipv4_count)]
                self.pointer_v4 = (self.pointer_v4 + ipv4_count) % size
            # Append IPv6.
            size = len(self.reliable_peers_v6)
            if ipv6_count > 0 and size <= ipv6_count:
                peers = peers + self.reliable_peers_v6
            elif ipv6_count > 0:
                peers = peers + [
                    self.reliable_peers_v6[i % size] for i in range(self.pointer_v6, self.pointer_v6 + ipv6_count)
                ]
                self.pointer_v6 = (self.pointer_v6 + ipv6_count) % size
            return peers

    async def dns_response(self, request: DNSRecord) -> Optional[DNSRecord]:
        try:
            ips = [self.soa_record] + self.ns_records
            ipv4_count = 0
            ipv6_count = 0
            if request.q.qtype == 1:
                ipv4_count = 32
            elif request.q.qtype == 28:
                ipv6_count = 32
            elif request.q.qtype == 255:
                ipv4_count = 16
                ipv6_count = 16
            else:
                ipv4_count = 32
            peers = await self.get_peers_to_respond(ipv4_count, ipv6_count)
            if len(peers) == 0:
                return None
            for peer in peers:
                ipv4 = True
                try:
                    _ = ipaddress.IPv4Address(peer)
                except ValueError:
                    ipv4 = False
                if ipv4:
                    ips.append(A(peer))
                else:
                    try:
                        _ = ipaddress.IPv6Address(peer)
                    except ValueError:
                        continue
                    ips.append(AAAA(peer))
            reply: DNSRecord = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=len(ips), ra=1), q=request.q)

            records = {
                self.domain: ips,
                self.domain.ns1: [A(IP)],  # MX and NS records must never point to a CNAME alias (RFC 2181 section 10.3)
                self.domain.ns2: [A(IP)],
            }

            qname = request.q.qname  # question, and the domain for the question, so the auctual thing being asked for.
            # DNS labels are mixed case with DNS resolvers that implement the use of bit 0x20 to improve
            # transaction identity. See https://datatracker.ietf.org/doc/html/draft-vixie-dnsext-dns0x20-00
            qn = str(qname).lower()
            qtype = request.q.qtype
            qt = QTYPE[qtype]
            if qn == self.domain or qn.endswith("." + self.domain):
                for name, rrs in records.items():
                    if name == qn:  # if the dns name is the same as the question name
                        for rdata in rrs:
                            rqt = rdata.__class__.__name__
                            if qt in ["*", rqt] or (qt == "ANY" and (rqt == "A" or rqt == "AAAA")):
                                reply.add_answer(
                                    RR(rname=qname, rtype=getattr(QTYPE, rqt), rclass=1, ttl=self.ttl, rdata=rdata)
                                )
                # always put nameservers and the SOA records
                for nameserver in self.ns_records:
                    reply.add_ar(RR(rname=self.domain, rtype=QTYPE.NS, rclass=1, ttl=self.ttl, rdata=nameserver))
                reply.add_auth(RR(rname=self.domain, rtype=QTYPE.SOA, rclass=1, ttl=self.ttl, rdata=self.soa_record))
            return reply
        except Exception as e:
            log.error(f"Exception: {e}. Traceback: {traceback.format_exc()}.")
            return None


async def serve_dns(config: Dict[str, Any], root_path: Path) -> None:
    dns_server = DNSServer(config, root_path)
    async with dns_server.run():
        await dns_server.shutdown_event.wait()  # this is released on SIGINT or SIGTERM or any unhandled exception


def main() -> None:
    root_path = DEFAULT_ROOT_PATH
    config = load_config(root_path, "config.yaml", SERVICE_NAME)
    initialize_logging(SERVICE_NAME, config["logging"], root_path)
    asyncio.run(serve_dns(config=config, root_path=root_path))


if __name__ == "__main__":
    main()

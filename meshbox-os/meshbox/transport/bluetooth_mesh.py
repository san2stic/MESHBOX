"""
Bluetooth Low Energy Mesh Transport for MeshBox

Provides offline mesh networking via BLE with:
- GAP/GATT-based peer discovery
- Mesh message relay via BLE bridges
- Low-power advertising and scanning
- Characteristic-based data exchange
"""

from __future__ import annotations

import asyncio
import logging
import struct
import time
from typing import Optional, Callable, Any
from dataclasses import dataclass, field
from enum import Enum

from meshbox.transport import (
    TransportProtocol,
    TransportType,
    ConnectionState,
    TransportStats,
    PeerEndpoint,
)

logger = logging.getLogger("meshbox.transport.bluetooth")

MESHBOX_BLE_SERVICE_UUID = "12345678-1234-1234-1234-123456789abc"
MESHBOX_BLE_CHARACTERISTIC_UUID = "12345678-1234-1234-1234-123456789abd"
MESHBOX_BLE_NAME_PREFIX = "MB-"
MAX_BLE_PAYLOAD_SIZE = 512
BLE_SCAN_DURATION = 5.0
BLE_ADVERTISE_INTERVAL = 100


class BTDeviceType(Enum):
    CENTRAL = "central"
    PERIPHERAL = "peripheral"
    DUAL = "dual"


@dataclass
class BLEPeerDevice:
    peer_id: str
    address: str
    name: str
    rssi: int = -100
    last_seen: float = field(default_factory=time.time)
    connection_state: ConnectionState = ConnectionState.DISCONNECTED
    tx_count: int = 0
    rx_count: int = 0


class BLEService:
    """GATT service definition for MeshBox BLE mesh."""

    SERVICE_UUID = MESHBOX_BLE_SERVICE_UUID
    MESSAGE_CHAR_UUID = MESHBOX_BLE_CHARACTERISTIC_UUID
    MESH_CONTROL_UUID = "12345678-1234-1234-1234-123456789abe"

    def __init__(self, local_peer_id: str, profile_data: dict):
        self.local_peer_id = local_peer_id
        self.profile_data = profile_data
        self.manufacturer_data = self._build_manufacturer_data()
        self.service_data = self._build_service_data()

    def _build_manufacturer_data(self) -> bytes:
        fp = self.profile_data.get("fingerprint", self.local_peer_id)[:8].encode()
        return fp

    def _build_service_data(self) -> bytes:
        data = {
            "fp": self.local_peer_id[:8],
            "v": 1,
            "ts": int(time.time()),
        }
        return str(data).encode()


class BLEScanner:
    """BLE scanner for discovering nearby MeshBox peers."""

    def __init__(self, on_peer_discovered: Callable[[BLEPeerDevice], None] = None):
        self.on_peer_discovered = on_peer_discovered
        self.discovered_peers: dict[str, BLEPeerDevice] = {}
        self._scanning = False
        self._scanner = None

    async def start(self) -> None:
        """Start scanning for BLE devices."""
        try:
            from bleak import BleakScanner
        except ImportError:
            logger.warning("bleak not installed - BLE scanning disabled")
            return

        self._scanning = True
        self._scanner = BleakScanner()
        self._scanner.register_detection_callback(self._on_device_discovered)

        try:
            await self._scanner.start()
            logger.info("BLE scanner started")
            while self._scanning:
                await asyncio.sleep(BLE_SCAN_DURATION)
        except Exception as e:
            logger.error(f"BLE scanner error: {e}")
        finally:
            await self.stop()

    async def stop(self) -> None:
        """Stop scanning."""
        self._scanning = False
        if self._scanner:
            try:
                await self._scanner.stop()
            except Exception:
                pass
        logger.info("BLE scanner stopped")

    def _on_device_discovered(self, device: Any, advertisement_data: Any) -> None:
        """Handle discovered BLE device."""
        name = device.name or ""
        if not name.startswith(MESHBOX_BLE_NAME_PREFIX):
            return

        peer_fp = name[len(MESHBOX_BLE_NAME_PREFIX):]
        rssi = getattr(advertisement_data, "rssi", -100)

        peer = BLEPeerDevice(
            peer_id=peer_fp,
            address=device.address,
            name=name,
            rssi=rssi,
            last_seen=time.time(),
        )

        is_new = peer_fp not in self.discovered_peers
        self.discovered_peers[peer_fp] = peer

        if is_new:
            logger.info(f"BLE peer discovered: {name} RSSI={rssi}")
            if self.on_peer_discovered:
                asyncio.create_task(self._notify_discovered(peer))

    async def _notify_discovered(self, peer: BLEPeerDevice) -> None:
        """Notify peer discovered callback."""
        if self.on_peer_discovered:
            self.on_peer_discovered(peer)

    def get_peers(self) -> list[BLEPeerDevice]:
        """Get all discovered peers."""
        return list(self.discovered_peers.values())

    def get_peer(self, peer_id: str) -> Optional[BLEPeerDevice]:
        """Get a specific peer."""
        return self.discovered_peers.get(peer_id)


class BLEAdvertiser:
    """BLE advertiser for broadcasting our presence."""

    def __init__(self, local_peer_id: str, profile_data: dict):
        self.local_peer_id = local_peer_id
        self.profile_data = profile_data
        self._advertising = False
        self._advertiser = None

    async def start(self) -> None:
        """Start advertising our presence."""
        try:
            from bleak import BleakAdvertiser
        except ImportError:
            logger.warning("bleak not installed - BLE advertising disabled")
            return

        self._advertising = True
        adv_name = f"{MESHBOX_BLE_NAME_PREFIX}{self.local_peer_id[:8]}"

        service_data = {
            "uuid": MESHBOX_BLE_SERVICE_UUID,
            "data": self._build_service_data(),
        }

        manufacturer_data = {
            "manufacturer_id": 0xFFFF,
            "data": self.local_peer_id[:8].encode(),
        }

        try:
            self._advertiser = BleakAdvertiser(
                service_uuids=[MESHBOX_BLE_SERVICE_UUID],
                name=adv_name,
                manufacturer_data=manufacturer_data,
                service_data=service_data,
            )
            await self._advertiser.start()
            logger.info(f"BLE advertiser started: {adv_name}")
        except Exception as e:
            logger.error(f"BLE advertising error: {e}")

    async def stop(self) -> None:
        """Stop advertising."""
        self._advertising = False
        if self._advertiser:
            try:
                await self._advertiser.stop()
            except Exception:
                pass
        logger.info("BLE advertiser stopped")

    def _build_service_data(self) -> bytes:
        data = {
            "fp": self.local_peer_id[:8],
            "v": 1,
        }
        import json
        return json.dumps(data).encode()


class BLEGattClient:
    """GATT client for connecting to BLE peers and exchanging data."""

    def __init__(self, device: BLEPeerDevice):
        self.device = device
        self._client = None
        self._connected = False

    async def connect(self, timeout: float = 10.0) -> bool:
        """Connect to a BLE peer."""
        try:
            from bleak import BleakClient
        except ImportError:
            return False

        try:
            self._client = BleakClient(self.device.address, timeout=timeout)
            await self._client.connect()
            self._connected = True
            self.device.connection_state = ConnectionState.CONNECTED
            logger.info(f"BLE connected to {self.device.name}")
            return True
        except Exception as e:
            logger.error(f"BLE connect failed to {self.device.name}: {e}")
            return False

    async def disconnect(self) -> None:
        """Disconnect from a BLE peer."""
        if self._client and self._connected:
            try:
                await self._client.disconnect()
            except Exception:
                pass
        self._connected = False
        self.device.connection_state = ConnectionState.DISCONNECTED

    async def write_message(self, data: bytes) -> bool:
        """Write a message to the peer."""
        if not self._connected or not self._client:
            return False

        try:
            await self._client.write_gatt_char(
                MESHBOX_BLE_CHARACTERISTIC_UUID,
                data,
                response=False,
            )
            self.device.tx_count += 1
            return True
        except Exception as e:
            logger.error(f"BLE write failed: {e}")
            return False

    async def read_message(self) -> Optional[bytes]:
        """Read a message from the peer."""
        if not self._connected or not self._client:
            return None

        try:
            data = await self._client.read_gatt_char(MESHBOX_BLE_CHARACTERISTIC_UUID)
            self.device.rx_count += 1
            return data
        except Exception as e:
            logger.debug(f"BLE read failed: {e}")
            return None

    def is_connected(self) -> bool:
        """Check if connected."""
        return self._connected


class BLEMeshTransport(TransportProtocol):
    """
    Bluetooth Low Energy mesh transport for MeshBox.

    Supports:
    - Peer discovery via BLE scanning
    - Data exchange via GATT characteristics
    - Mesh relay via connected bridges
    - Offline-first communication
    """

    def __init__(
        self,
        local_peer_id: str,
        profile_data: dict,
        device_type: BTDeviceType = BTDeviceType.DUAL,
    ):
        super().__init__(local_peer_id)
        self.profile_data = profile_data
        self.device_type = device_type
        self.scanner = BLEScanner(on_peer_discovered=self._on_peer_discovered)
        self.advertiser = BLEAdvertiser(local_peer_id, profile_data)
        self.connected_peers: dict[str, BLEGattClient] = {}
        self.mesh_buffer: list[tuple[bytes, float]] = []
        self._relay_hops: int = 3
        self._running = False

    @property
    def transport_type(self) -> TransportType:
        return TransportType.BLUETOOTH_LE

    async def start(self) -> None:
        """Start the BLE transport."""
        self._running = True
        self.state = ConnectionState.CONNECTED
        logger.info(f"BLE mesh transport started ({self.device_type.value})")

        if self.device_type in (BTDeviceType.CENTRAL, BTDeviceType.DUAL):
            asyncio.create_task(self.scanner.start())

        if self.device_type in (BTDeviceType.PERIPHERAL, BTDeviceType.DUAL):
            asyncio.create_task(self.advertiser.start())

    async def stop(self) -> None:
        """Stop the BLE transport."""
        self._running = False

        for peer_id in list(self.connected_peers.keys()):
            await self.disconnect(peer_id)

        await self.scanner.stop()
        await self.advertiser.stop()
        self.state = ConnectionState.DISCONNECTED
        logger.info("BLE mesh transport stopped")

    async def connect(self, endpoint: PeerEndpoint) -> bool:
        """Connect to a BLE peer."""
        device = self.scanner.get_peer(endpoint.peer_id)
        if not device:
            logger.warning(f"BLE peer not found: {endpoint.peer_id}")
            return False

        if endpoint.peer_id in self.connected_peers:
            return True

        client = BLEGattClient(device)
        success = await client.connect()

        if success:
            self.connected_peers[endpoint.peer_id] = client
            self.stats.connections_opened += 1
        else:
            self.stats.connections_failed += 1

        return success

    async def disconnect(self, peer_id: str) -> None:
        """Disconnect from a BLE peer."""
        client = self.connected_peers.pop(peer_id, None)
        if client:
            await client.disconnect()
            logger.info(f"BLE disconnected from {peer_id}")

    async def send(self, peer_id: str, data: bytes) -> bool:
        """Send data to a connected BLE peer."""
        client = self.connected_peers.get(peer_id)
        if not client:
            logger.debug(f"No BLE connection for {peer_id}")
            return False

        if len(data) > MAX_BLE_PAYLOAD_SIZE:
            chunks = [data[i:i + MAX_BLE_PAYLOAD_SIZE] for i in range(0, len(data), MAX_BLE_PAYLOAD_SIZE)]
            success = True
            for chunk in chunks:
                if not await client.write_message(chunk):
                    success = False
                    break
            if success:
                self._update_stats(sent=len(data), msg_sent=1)
            return success

        success = await client.write_message(data)
        if success:
            self._update_stats(sent=len(data), msg_sent=1)
        return success

    async def broadcast(self, data: bytes) -> int:
        """Broadcast data to all connected BLE peers."""
        count = 0
        for peer_id, client in self.connected_peers.items():
            if client.is_connected():
                try:
                    await client.write_message(data)
                    count += 1
                except Exception as e:
                    logger.debug(f"BLE broadcast to {peer_id} failed: {e}")
        self._update_stats(sent=len(data) * count, msg_sent=count)
        return count

    async def relay_message(
        self, data: bytes, source_peer: str, max_hops: int = None
    ) -> int:
        """Relay a message through the BLE mesh."""
        if max_hops is None:
            max_hops = self._relay_hops

        relay_count = 0
        for peer_id, client in self.connected_peers.items():
            if peer_id != source_peer and client.is_connected():
                try:
                    await client.write_message(data)
                    relay_count += 1
                except Exception as e:
                    logger.debug(f"BLE relay to {peer_id} failed: {e}")

        return relay_count

    def buffer_message(self, data: bytes, ttl: float = 60.0) -> None:
        """Buffer a message for later relay when peers become available."""
        self.mesh_buffer.append((data, time.time() + ttl))

    def get_buffered_messages(self) -> list[bytes]:
        """Get and clear buffered messages that haven't expired."""
        now = time.time()
        messages = []
        self.mesh_buffer = [
            (data, expiry) for data, expiry in self.mesh_buffer if expiry > now
        ]
        for data, _ in self.mesh_buffer:
            messages.append(data)
        return messages

    def _on_peer_discovered(self, peer: BLEPeerDevice) -> None:
        """Handle discovered BLE peer."""
        logger.info(f"BLE peer discovered: {peer.name} RSSI={peer.rssi}")

    def _update_stats(self, sent: int = 0, received: int = 0,
                      msg_sent: int = 0, msg_recv: int = 0) -> None:
        """Update transport statistics."""
        super()._update_stats(sent, received, msg_sent, msg_recv)

    def get_connection_stats(self) -> dict:
        """Get detailed BLE connection statistics."""
        return {
            "connected_peers": len(self.connected_peers),
            "discovered_peers": len(self.scanner.discovered_peers),
            "buffered_messages": len(self.mesh_buffer),
            "relay_hops": self._relay_hops,
        }


class BLEMeshBridge:
    """
    Bridge between BLE mesh and IP network.
    Enables messages to flow between BLE and other transports.
    """

    def __init__(
        self,
        ble_transport: BLEMeshTransport,
        ip_transport: TransportProtocol,
    ):
        self.ble_transport = ble_transport
        self.ip_transport = ip_transport
        self._bridge_enabled = False
        self._pending_messages: list[dict] = []

    def enable_bridge(self) -> None:
        """Enable BLE/IP bridging."""
        self._bridge_enabled = True
        self.ble_transport.on_message = self._on_ble_message
        self.ip_transport.on_message = self._on_ip_message
        logger.info("BLE/IP bridge enabled")

    def disable_bridge(self) -> None:
        """Disable BLE/IP bridging."""
        self._bridge_enabled = False
        logger.info("BLE/IP bridge disabled")

    async def _on_ble_message(self, peer_id: str, data: bytes) -> None:
        """Forward BLE messages to IP network."""
        if not self._bridge_enabled:
            return

        if self.ip_transport.transport_type == TransportType.TCP:
            try:
                import json
                msg = json.loads(data)
                msg["via_ble_bridge"] = True
                await self.ip_transport.broadcast(json.dumps(msg).encode())
            except Exception as e:
                logger.error(f"BLE->IP bridge error: {e}")

    async def _on_ip_message(self, peer_id: str, data: bytes) -> None:
        """Forward IP messages to BLE mesh."""
        if not self._bridge_enabled:
            return

        await self.ble_transport.broadcast(data)

    async def flush_pending(self) -> int:
        """Flush pending messages through the bridge."""
        count = 0
        for msg in self._pending_messages:
            if msg.get("via") == "ble":
                success = await self.ip_transport.broadcast(msg["data"])
            else:
                success = await self.ble_transport.broadcast(msg["data"])
            if success:
                count += 1
        self._pending_messages.clear()
        return count

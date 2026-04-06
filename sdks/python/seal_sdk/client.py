"""
Seal DAO client — communicates with a Seal node over JSON-RPC.

All cryptographic operations use post-quantum algorithms:
- ML-DSA-65 (FIPS 204) for digital signatures
- ML-KEM-768 (FIPS 203) for key encapsulation
- SHA3-256 (FIPS 202) for hashing

NOTE: This is a scaffold. Method implementations will be connected once the
Seal node's JSON-RPC interface is finalized.
"""

from __future__ import annotations

from seal_sdk.types import Block, NetworkInfo, QueryResult


class SealClient:
    """Client for interacting with a Seal DAO node.

    Communicates over JSON-RPC with the node's HTTP endpoint.

    Example::

        client = SealClient("http://localhost:9944")
        await client.connect()

        result = await client.submit_sql("SELECT * FROM users LIMIT 10")
        block = await client.get_block(0)
        balance = await client.get_balance("seal1...")

        await client.disconnect()
    """

    def __init__(self, rpc_url: str) -> None:
        """Create a new Seal client.

        Args:
            rpc_url: The URL of the Seal node's JSON-RPC endpoint
                     (e.g., "http://localhost:9944").

        Raises:
            ValueError: If rpc_url is empty.
        """
        if not rpc_url:
            raise ValueError("rpc_url is required")
        self._rpc_url = rpc_url.rstrip("/")
        self._connected = False

    @property
    def rpc_url(self) -> str:
        """The RPC endpoint URL."""
        return self._rpc_url

    @property
    def is_connected(self) -> bool:
        """Whether the client is currently connected."""
        return self._connected

    async def connect(self) -> None:
        """Connect to the Seal node and verify reachability.

        Raises:
            NotImplementedError: RPC interface not yet available.
        """
        # TODO: Perform a health-check RPC call (e.g., seal_getNetworkInfo)
        # to verify the node is reachable and compatible.
        self._connected = True

    async def disconnect(self) -> None:
        """Disconnect from the Seal node and release resources."""
        self._connected = False

    async def submit_sql(self, sql: str) -> QueryResult:
        """Submit a SQL statement for execution on the Seal database layer.

        Supports PostgreSQL-compatible syntax: SELECT, INSERT, UPDATE, DELETE,
        CREATE TABLE, CREATE POLICY, CREATE INDEX, ALTER TABLE.

        Args:
            sql: The SQL statement to execute.

        Returns:
            The query result including columns, rows, and execution metadata.

        Raises:
            NotImplementedError: RPC interface not yet available.
            ConnectionError: If not connected.
        """
        self._ensure_connected()
        raise NotImplementedError(
            "seal_submitSql RPC is not yet implemented. "
            "The Seal node JSON-RPC interface is under development. "
            "See SPEC.md for the planned RPC API."
        )

    async def get_block(self, height: int) -> Block:
        """Fetch a block by height.

        Args:
            height: The block height (0-indexed).

        Returns:
            The block at the given height.

        Raises:
            NotImplementedError: RPC interface not yet available.
            ConnectionError: If not connected.
        """
        self._ensure_connected()
        raise NotImplementedError(
            "seal_getBlock RPC is not yet implemented. "
            "The Seal node JSON-RPC interface is under development. "
            "See SPEC.md for the planned RPC API."
        )

    async def get_balance(self, address: str) -> int:
        """Get the SEAL token balance of an address.

        Balances are in micro-SEAL (9 decimal places).
        1 SEAL = 1_000_000_000 micro-SEAL.

        Args:
            address: The bech32m-encoded Seal address.

        Returns:
            The balance in micro-SEAL.

        Raises:
            NotImplementedError: RPC interface not yet available.
            ConnectionError: If not connected.
        """
        self._ensure_connected()
        raise NotImplementedError(
            "seal_getBalance RPC is not yet implemented. "
            "The Seal node JSON-RPC interface is under development. "
            "See SPEC.md for the planned RPC API."
        )

    async def transfer(self, to: str, amount: int) -> str:
        """Transfer SEAL tokens to another address.

        The transaction is signed locally with ML-DSA-65 and submitted
        to the node.

        Args:
            to: The recipient's bech32m-encoded Seal address.
            amount: The amount to transfer in micro-SEAL.

        Returns:
            The transaction hash (SHA3-256, hex-encoded).

        Raises:
            NotImplementedError: RPC interface not yet available.
            ConnectionError: If not connected.
        """
        self._ensure_connected()
        raise NotImplementedError(
            "seal_transfer RPC is not yet implemented. "
            "The Seal node JSON-RPC interface is under development. "
            "See SPEC.md for the planned RPC API."
        )

    async def get_network_info(self) -> NetworkInfo:
        """Get network information (chain ID, latest block, epoch, validators).

        Returns:
            Current network status.

        Raises:
            NotImplementedError: RPC interface not yet available.
            ConnectionError: If not connected.
        """
        self._ensure_connected()
        raise NotImplementedError(
            "seal_getNetworkInfo RPC is not yet implemented. "
            "The Seal node JSON-RPC interface is under development. "
            "See SPEC.md for the planned RPC API."
        )

    def _ensure_connected(self) -> None:
        """Raise ConnectionError if not connected."""
        if not self._connected:
            raise ConnectionError(
                "Not connected. Call 'await client.connect()' first."
            )

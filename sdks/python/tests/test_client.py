"""Tests for the Seal DAO Python SDK scaffold."""

import pytest

from seal_sdk import Block, QueryResult, SealClient, Transaction
from seal_sdk.types import ColumnDef, NetworkInfo, Row


class TestSealClientCreation:
    """Test SealClient construction and basic properties."""

    def test_create_client(self):
        client = SealClient("http://localhost:9944")
        assert client.rpc_url == "http://localhost:9944"
        assert not client.is_connected

    def test_create_client_strips_trailing_slash(self):
        client = SealClient("http://localhost:9944/")
        assert client.rpc_url == "http://localhost:9944"

    def test_create_client_empty_url_raises(self):
        with pytest.raises(ValueError, match="rpc_url is required"):
            SealClient("")


class TestSealClientConnection:
    """Test connect/disconnect behavior."""

    @pytest.mark.asyncio
    async def test_connect_sets_connected(self):
        client = SealClient("http://localhost:9944")
        assert not client.is_connected
        await client.connect()
        assert client.is_connected

    @pytest.mark.asyncio
    async def test_disconnect_clears_connected(self):
        client = SealClient("http://localhost:9944")
        await client.connect()
        await client.disconnect()
        assert not client.is_connected


class TestSealClientMethods:
    """Test that stub methods raise NotImplementedError with helpful messages."""

    @pytest.mark.asyncio
    async def test_submit_sql_raises_not_implemented(self):
        client = SealClient("http://localhost:9944")
        await client.connect()
        with pytest.raises(NotImplementedError, match="seal_submitSql"):
            await client.submit_sql("SELECT 1")

    @pytest.mark.asyncio
    async def test_get_block_raises_not_implemented(self):
        client = SealClient("http://localhost:9944")
        await client.connect()
        with pytest.raises(NotImplementedError, match="seal_getBlock"):
            await client.get_block(0)

    @pytest.mark.asyncio
    async def test_get_balance_raises_not_implemented(self):
        client = SealClient("http://localhost:9944")
        await client.connect()
        with pytest.raises(NotImplementedError, match="seal_getBalance"):
            await client.get_balance("seal1abc")

    @pytest.mark.asyncio
    async def test_transfer_raises_not_implemented(self):
        client = SealClient("http://localhost:9944")
        await client.connect()
        with pytest.raises(NotImplementedError, match="seal_transfer"):
            await client.transfer("seal1abc", 1000)

    @pytest.mark.asyncio
    async def test_get_network_info_raises_not_implemented(self):
        client = SealClient("http://localhost:9944")
        await client.connect()
        with pytest.raises(NotImplementedError, match="seal_getNetworkInfo"):
            await client.get_network_info()


class TestSealClientNotConnected:
    """Test that methods raise ConnectionError when not connected."""

    @pytest.mark.asyncio
    async def test_submit_sql_not_connected(self):
        client = SealClient("http://localhost:9944")
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.submit_sql("SELECT 1")

    @pytest.mark.asyncio
    async def test_get_block_not_connected(self):
        client = SealClient("http://localhost:9944")
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.get_block(0)


class TestTypes:
    """Test that all type definitions exist and are constructable."""

    def test_block_defaults(self):
        block = Block()
        assert block.height == 0
        assert block.hash == ""
        assert block.transactions == []

    def test_transaction_defaults(self):
        tx = Transaction()
        assert tx.hash == ""
        assert tx.amount == 0
        assert tx.sql is None

    def test_query_result_defaults(self):
        result = QueryResult()
        assert result.columns == []
        assert result.rows == []
        assert result.rows_affected == 0

    def test_column_def(self):
        col = ColumnDef(name="id", data_type="BIGINT", nullable=False, primary_key=True)
        assert col.name == "id"
        assert col.data_type == "BIGINT"
        assert not col.nullable
        assert col.primary_key

    def test_row(self):
        row = Row(values=[1, "alice", True])
        assert len(row.values) == 3

    def test_network_info(self):
        info = NetworkInfo(chain_id="seal-mainnet", latest_height=42)
        assert info.chain_id == "seal-mainnet"
        assert info.latest_height == 42

    def test_block_with_transactions(self):
        tx = Transaction(hash="abc123", from_address="seal1sender", amount=1000)
        block = Block(height=1, hash="def456", transactions=[tx])
        assert len(block.transactions) == 1
        assert block.transactions[0].hash == "abc123"

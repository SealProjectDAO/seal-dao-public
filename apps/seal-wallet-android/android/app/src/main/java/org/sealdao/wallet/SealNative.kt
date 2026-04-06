package org.sealdao.wallet

/**
 * JNI bridge to the Rust seal-wallet-ffi library.
 *
 * Uses JNI_OnLoad registration — no name mangling needed.
 */
object SealNative {
    private var loaded = false

    fun ensureLoaded() {
        if (!loaded) {
            System.loadLibrary("seal_wallet_ffi")
            loaded = true
        }
    }

    fun createWallet(testnet: Boolean = true): String {
        ensureLoaded()
        return nativeCreateWallet(if (testnet) 1 else 0)
    }

    fun importFromHex(mnemonicHex: String, testnet: Boolean = true): String {
        ensureLoaded()
        return nativeImportWallet(mnemonicHex, if (testnet) 1 else 0)
    }

    fun importFromWords(words: String, testnet: Boolean = true): String {
        ensureLoaded()
        return nativeImportWalletBip39(words, if (testnet) 1 else 0)
    }

    fun getAddress(): String {
        ensureLoaded()
        return nativeGetAddress()
    }

    fun sign(message: String): String {
        ensureLoaded()
        return nativeSignMessage(message)
    }

    fun verify(message: String, signatureHex: String): Boolean {
        ensureLoaded()
        return nativeVerifySignature(message, signatureHex) == 1
    }

    fun exportMnemonicHex(): String {
        ensureLoaded()
        return nativeExportMnemonic()
    }

    fun exportMnemonicBip39(): String {
        ensureLoaded()
        return nativeExportMnemonicBip39()
    }

    // --- Node RPC ---

    fun rpcGetHeight(nodeUrl: String): String {
        ensureLoaded()
        return nativeRpcGetHeight(nodeUrl)
    }

    fun rpcQuery(nodeUrl: String, sql: String): String {
        ensureLoaded()
        return nativeRpcQuery(nodeUrl, sql)
    }

    fun rpcSend(nodeUrl: String, sql: String): String {
        ensureLoaded()
        return nativeRpcSend(nodeUrl, sql)
    }

    fun rpcMpc(nodeUrl: String, function: String, table: String, column: String): String {
        ensureLoaded()
        return nativeRpcMpc(nodeUrl, function, table, column)
    }

    fun rpcZkProve(nodeUrl: String, table: String, statement: String): String {
        ensureLoaded()
        return nativeRpcZkProve(nodeUrl, table, statement)
    }

    // Private native methods — registered via JNI_OnLoad
    private external fun nativeCreateWallet(testnet: Int): String
    private external fun nativeImportWallet(mnemonicHex: String, testnet: Int): String
    private external fun nativeImportWalletBip39(words: String, testnet: Int): String
    private external fun nativeGetAddress(): String
    private external fun nativeGetWalletInfo(): String
    private external fun nativeExportMnemonic(): String
    private external fun nativeExportMnemonicBip39(): String
    private external fun nativeSignMessage(message: String): String
    private external fun nativeVerifySignature(message: String, signatureHex: String): Int
    private external fun nativeRpcGetHeight(nodeUrl: String): String
    private external fun nativeRpcQuery(nodeUrl: String, sql: String): String
    private external fun nativeRpcSend(nodeUrl: String, sql: String): String
    private external fun nativeRpcMpc(nodeUrl: String, function: String, table: String, column: String): String
    private external fun nativeRpcZkProve(nodeUrl: String, table: String, statement: String): String
}

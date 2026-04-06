package org.sealdao.wallet

import android.os.Bundle
import android.view.View
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.button.MaterialButton

class MainActivity : AppCompatActivity() {

    private lateinit var statusBadge: TextView
    private lateinit var addressText: TextView
    private lateinit var mnemonicCard: LinearLayout
    private lateinit var mnemonicText: TextView
    private lateinit var cryptoSection: LinearLayout
    private lateinit var messageInput: EditText
    private lateinit var signatureCard: LinearLayout
    private lateinit var signatureText: TextView
    private lateinit var verifyResult: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        statusBadge = findViewById(R.id.statusBadge)
        addressText = findViewById(R.id.addressText)
        mnemonicCard = findViewById(R.id.mnemonicCard)
        mnemonicText = findViewById(R.id.mnemonicText)
        cryptoSection = findViewById(R.id.cryptoSection)
        messageInput = findViewById(R.id.messageInput)
        signatureCard = findViewById(R.id.signatureCard)
        signatureText = findViewById(R.id.signatureText)
        verifyResult = findViewById(R.id.verifyResult)

        findViewById<MaterialButton>(R.id.btnCreate).setOnClickListener { createWallet() }
        findViewById<MaterialButton>(R.id.btnImport).setOnClickListener { showImportDialog() }
        findViewById<MaterialButton>(R.id.btnSign).setOnClickListener { signMessage() }
    }

    private fun createWallet() {
        try {
            val address = SealNative.createWallet(testnet = true)
            onWalletReady(address)

            // Show mnemonic
            val bip39 = SealNative.exportMnemonicBip39()
            mnemonicText.text = bip39
            mnemonicCard.visibility = View.VISIBLE
        } catch (e: Exception) {
            Toast.makeText(this, "Failed to create wallet: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    private fun showImportDialog() {
        val items = arrayOf("Hex Seed (64 chars)", "BIP-39 Words (24 words)")
        AlertDialog.Builder(this, R.style.Theme_SealWallet)
            .setTitle("Import Wallet")
            .setItems(items) { _, which ->
                when (which) {
                    0 -> showImportHexDialog()
                    1 -> showImportWordsDialog()
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun showImportHexDialog() {
        val input = EditText(this).apply {
            hint = "64-character hex seed"
            setTextColor(0xFFE8E8ED.toInt())
            setHintTextColor(0xFF606070.toInt())
            setBackgroundColor(0xFF1A1A26.toInt())
            setPadding(32, 24, 32, 24)
            inputType = android.text.InputType.TYPE_CLASS_TEXT
        }

        AlertDialog.Builder(this, R.style.Theme_SealWallet)
            .setTitle("Restore from Hex Seed")
            .setView(input)
            .setPositiveButton("Restore") { _, _ ->
                val hex = input.text.toString().trim()
                if (hex.isNotEmpty()) {
                    try {
                        val address = SealNative.importFromHex(hex, testnet = true)
                        onWalletReady(address)
                        mnemonicCard.visibility = View.GONE
                    } catch (e: Exception) {
                        Toast.makeText(this, "Restore failed: ${e.message}", Toast.LENGTH_LONG).show()
                    }
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun showImportWordsDialog() {
        val input = EditText(this).apply {
            hint = "Enter BIP-39 mnemonic words"
            setTextColor(0xFFE8E8ED.toInt())
            setHintTextColor(0xFF606070.toInt())
            setBackgroundColor(0xFF1A1A26.toInt())
            setPadding(32, 24, 32, 24)
        }

        AlertDialog.Builder(this, R.style.Theme_SealWallet)
            .setTitle("Import from BIP-39")
            .setView(input)
            .setPositiveButton("Import") { _, _ ->
                val words = input.text.toString().trim()
                if (words.isNotEmpty()) {
                    try {
                        val address = SealNative.importFromWords(words, testnet = true)
                        onWalletReady(address)
                        mnemonicCard.visibility = View.GONE
                    } catch (e: Exception) {
                        Toast.makeText(this, "Import failed: ${e.message}", Toast.LENGTH_LONG).show()
                    }
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun onWalletReady(address: String) {
        addressText.text = address
        statusBadge.text = "  Testnet  "
        statusBadge.setTextColor(0xFF4ADE80.toInt())
        statusBadge.setBackgroundColor(0x334ADE80)
        cryptoSection.visibility = View.VISIBLE

        findViewById<MaterialButton>(R.id.btnCreate).text = "Create New Wallet (reset)"
    }

    private fun signMessage() {
        val message = messageInput.text.toString()
        if (message.isEmpty()) {
            Toast.makeText(this, "Enter a message to sign", Toast.LENGTH_SHORT).show()
            return
        }

        try {
            val sigHex = SealNative.sign(message)

            if (sigHex.isEmpty()) {
                Toast.makeText(this, "Signing failed — no wallet loaded", Toast.LENGTH_SHORT).show()
                return
            }

            // Show signature (truncated)
            val display = if (sigHex.length > 64) {
                "${sigHex.substring(0, 32)}...${sigHex.substring(sigHex.length - 32)}"
            } else sigHex

            signatureText.text = display
            signatureCard.visibility = View.VISIBLE

            // Verify
            val valid = SealNative.verify(message, sigHex)
            if (valid) {
                verifyResult.text = "✓ Signature verified (ML-DSA-65)"
                verifyResult.setTextColor(0xFF4ADE80.toInt())
            } else {
                verifyResult.text = "✗ Verification failed"
                verifyResult.setTextColor(0xFFF87171.toInt())
            }
        } catch (e: Exception) {
            Toast.makeText(this, "Sign failed: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }
}

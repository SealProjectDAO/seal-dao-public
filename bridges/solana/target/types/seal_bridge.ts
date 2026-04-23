/**
 * Program IDL in camelCase format in order to be used in JS/TS.
 *
 * Note that this is only a type helper and is not the actual IDL. The original
 * IDL can be found at `target/idl/seal_bridge.json`.
 */
export type SealBridge = {
  "address": "Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS",
  "metadata": {
    "name": "sealBridge",
    "version": "0.1.0",
    "spec": "0.1.0",
    "description": "Seal DAO <-> Solana bridge program (Anchor)"
  },
  "docs": [
    "Seal DAO <-> Solana Bridge Program (Skeleton)",
    "",
    "This program locks SOL/SPL tokens on Solana and emits events that",
    "the Seal DAO network monitors. Unlocks happen when the Seal DAO",
    "committee provides a threshold signature proving the burn on the",
    "Seal side.",
    "",
    "SKELETON: Real ML-DSA threshold signature verification is not yet",
    "implemented. The `verify_threshold_signature` function is a stub."
  ],
  "instructions": [
    {
      "name": "initialize",
      "docs": [
        "Initialize the bridge state PDA.",
        "Called once by the deployer to set up the bridge authority, vault,",
        "and the Seal committee's 32-byte verification key used by",
        "`verify_committee_sig` to authenticate unlocks.",
        "",
        "`committee_key` is shared between the bridge program and the Seal",
        "committee. It rotates each Seal epoch — rotation is done via the",
        "admin `rotate_committee_key` ix (TODO). For testnet it's whatever",
        "the `seal-node` committee broadcasts over P2P; mainnet will",
        "derive it from the Ringtail aggregate verification key."
      ],
      "discriminator": [
        175,
        175,
        109,
        31,
        13,
        152,
        155,
        237
      ],
      "accounts": [
        {
          "name": "bridgeState",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  98,
                  114,
                  105,
                  100,
                  103,
                  101,
                  95,
                  115,
                  116,
                  97,
                  116,
                  101
                ]
              }
            ]
          }
        },
        {
          "name": "authority",
          "writable": true,
          "signer": true
        },
        {
          "name": "systemProgram",
          "address": "11111111111111111111111111111111"
        }
      ],
      "args": [
        {
          "name": "committeeKey",
          "type": {
            "array": [
              "u8",
              32
            ]
          }
        }
      ]
    },
    {
      "name": "lockTokens",
      "docs": [
        "Lock SPL tokens in the bridge vault.",
        "Emits a LockEvent that Seal DAO relayers monitor."
      ],
      "discriminator": [
        136,
        11,
        32,
        232,
        161,
        117,
        54,
        211
      ],
      "accounts": [
        {
          "name": "bridgeState",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  98,
                  114,
                  105,
                  100,
                  103,
                  101,
                  95,
                  115,
                  116,
                  97,
                  116,
                  101
                ]
              }
            ]
          }
        },
        {
          "name": "lockRecord",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  108,
                  111,
                  99,
                  107,
                  95,
                  114,
                  101,
                  99,
                  111,
                  114,
                  100
                ]
              },
              {
                "kind": "account",
                "path": "bridge_state.nonce",
                "account": "bridgeState"
              }
            ]
          }
        },
        {
          "name": "sender",
          "writable": true,
          "signer": true
        },
        {
          "name": "senderTokenAccount",
          "writable": true
        },
        {
          "name": "vaultTokenAccount",
          "writable": true
        },
        {
          "name": "tokenProgram",
          "address": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
        },
        {
          "name": "systemProgram",
          "address": "11111111111111111111111111111111"
        }
      ],
      "args": [
        {
          "name": "amount",
          "type": "u64"
        },
        {
          "name": "sealAddress",
          "type": {
            "array": [
              "u8",
              32
            ]
          }
        }
      ]
    },
    {
      "name": "rotateCommitteeKey",
      "docs": [
        "Rotate the committee verification key. Restricted to the",
        "authority (admin) set at init. In production this is called by",
        "the admin on each Seal epoch transition."
      ],
      "discriminator": [
        254,
        50,
        45,
        94,
        156,
        100,
        1,
        218
      ],
      "accounts": [
        {
          "name": "bridgeState",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  98,
                  114,
                  105,
                  100,
                  103,
                  101,
                  95,
                  115,
                  116,
                  97,
                  116,
                  101
                ]
              }
            ]
          }
        },
        {
          "name": "authority",
          "signer": true,
          "relations": [
            "bridgeState"
          ]
        }
      ],
      "args": [
        {
          "name": "newKey",
          "type": {
            "array": [
              "u8",
              32
            ]
          }
        }
      ]
    },
    {
      "name": "unlockTokens",
      "docs": [
        "Unlock SPL tokens from the bridge vault.",
        "Requires a valid threshold signature from the Seal DAO committee",
        "proving that the corresponding tokens were burned on the Seal side."
      ],
      "discriminator": [
        233,
        35,
        95,
        159,
        37,
        185,
        47,
        88
      ],
      "accounts": [
        {
          "name": "bridgeState",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  98,
                  114,
                  105,
                  100,
                  103,
                  101,
                  95,
                  115,
                  116,
                  97,
                  116,
                  101
                ]
              }
            ]
          }
        },
        {
          "name": "authority",
          "signer": true,
          "relations": [
            "bridgeState"
          ]
        },
        {
          "name": "recipient"
        },
        {
          "name": "recipientTokenAccount",
          "writable": true
        },
        {
          "name": "vaultTokenAccount",
          "writable": true
        },
        {
          "name": "tokenProgram",
          "address": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
        }
      ],
      "args": [
        {
          "name": "amount",
          "type": "u64"
        },
        {
          "name": "nonce",
          "type": "u64"
        },
        {
          "name": "signature",
          "type": "bytes"
        }
      ]
    }
  ],
  "accounts": [
    {
      "name": "bridgeState",
      "discriminator": [
        6,
        190,
        226,
        198,
        76,
        100,
        157,
        198
      ]
    },
    {
      "name": "lockRecord",
      "discriminator": [
        157,
        145,
        17,
        26,
        171,
        35,
        61,
        131
      ]
    }
  ],
  "events": [
    {
      "name": "keyRotatedEvent",
      "discriminator": [
        86,
        94,
        88,
        127,
        189,
        142,
        67,
        81
      ]
    },
    {
      "name": "lockEvent",
      "discriminator": [
        76,
        37,
        6,
        186,
        14,
        42,
        253,
        15
      ]
    },
    {
      "name": "unlockEvent",
      "discriminator": [
        105,
        1,
        235,
        144,
        68,
        123,
        75,
        123
      ]
    }
  ],
  "errors": [
    {
      "code": 6000,
      "name": "invalidSignature",
      "msg": "Invalid threshold signature from Seal DAO committee"
    },
    {
      "code": 6001,
      "name": "insufficientBalance",
      "msg": "Insufficient balance for this operation"
    },
    {
      "code": 6002,
      "name": "alreadyProcessed",
      "msg": "This nonce has already been processed"
    }
  ],
  "types": [
    {
      "name": "bridgeState",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "authority",
            "docs": [
              "The authority that can perform admin operations"
            ],
            "type": "pubkey"
          },
          {
            "name": "totalLocked",
            "docs": [
              "Total tokens currently locked in the bridge vault"
            ],
            "type": "u64"
          },
          {
            "name": "nonce",
            "docs": [
              "Monotonically increasing nonce for lock records"
            ],
            "type": "u64"
          },
          {
            "name": "bump",
            "docs": [
              "PDA bump seed"
            ],
            "type": "u8"
          },
          {
            "name": "committeeKey",
            "docs": [
              "32-byte verification key for committee MACs (see",
              "`verify_committee_sig`). Rotated per Seal epoch via",
              "`rotate_committee_key`."
            ],
            "type": {
              "array": [
                "u8",
                32
              ]
            }
          }
        ]
      }
    },
    {
      "name": "keyRotatedEvent",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "authority",
            "type": "pubkey"
          },
          {
            "name": "timestamp",
            "type": "i64"
          }
        ]
      }
    },
    {
      "name": "lockEvent",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "sender",
            "type": "pubkey"
          },
          {
            "name": "amount",
            "type": "u64"
          },
          {
            "name": "sealAddress",
            "type": {
              "array": [
                "u8",
                32
              ]
            }
          },
          {
            "name": "nonce",
            "type": "u64"
          },
          {
            "name": "timestamp",
            "type": "i64"
          }
        ]
      }
    },
    {
      "name": "lockRecord",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "sender",
            "docs": [
              "Solana address of the sender who locked tokens"
            ],
            "type": "pubkey"
          },
          {
            "name": "amount",
            "docs": [
              "Amount of tokens locked"
            ],
            "type": "u64"
          },
          {
            "name": "sealAddress",
            "docs": [
              "Destination address on the Seal DAO network (32 bytes)"
            ],
            "type": {
              "array": [
                "u8",
                32
              ]
            }
          },
          {
            "name": "timestamp",
            "docs": [
              "Unix timestamp of the lock"
            ],
            "type": "i64"
          },
          {
            "name": "nonce",
            "docs": [
              "Nonce of this lock record"
            ],
            "type": "u64"
          }
        ]
      }
    },
    {
      "name": "unlockEvent",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "recipient",
            "type": "pubkey"
          },
          {
            "name": "amount",
            "type": "u64"
          },
          {
            "name": "nonce",
            "type": "u64"
          },
          {
            "name": "timestamp",
            "type": "i64"
          }
        ]
      }
    }
  ]
};

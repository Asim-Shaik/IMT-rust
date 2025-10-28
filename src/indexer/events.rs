use crate::errors::{IndexerError, IndexerResult};
use crate::tree::Commitment;

#[derive(Clone, Debug)]
pub struct EventFieldSpec {
    pub name: &'static str,
    pub size: usize,
    pub little_endian: bool,
}

#[derive(Clone, Debug)]
pub struct EventSpec {
    pub name: &'static str,
    pub discriminator: &'static [u8; 8],
    pub fields: &'static [EventFieldSpec],
    pub total_size: usize, // 0 = unknown/variable
}

#[derive(Clone, Debug)]
pub struct ParsedEvent<'a> {
    pub spec: &'static EventSpec,
    pub raw: &'a [u8],
}

pub struct EventRegistry {
    pub specs: &'static [&'static EventSpec],
}

impl EventRegistry {
    pub const fn new(specs: &'static [&'static EventSpec]) -> Self {
        Self { specs }
    }

    pub fn identify(&self, bytes: &[u8]) -> Option<&'static EventSpec> {
        if bytes.len() < 8 {
            return None;
        }
        let disc = &bytes[..8];
        for spec in self.specs.iter() {
            if &spec.discriminator[..] == disc {
                return Some(spec);
            }
        }
        None
    }

    pub fn parse<'a>(&self, bytes: &'a [u8]) -> IndexerResult<Option<ParsedEvent<'a>>> {
        if let Some(spec) = self.identify(bytes) {
            if spec.total_size > 0 && bytes.len() < spec.total_size {
                return Err(IndexerError::InvalidData(format!(
                    "insufficient bytes for {}: expected {}, got {}",
                    spec.name,
                    spec.total_size,
                    bytes.len()
                )));
            }
            Ok(Some(ParsedEvent { spec, raw: bytes }))
        } else {
            Ok(None)
        }
    }
}

// Example specs from your JS constants (subset). Extend as needed.
pub const TRANSFER_BETWEEN_ACCOUNTS_CB_FIELDS: &[EventFieldSpec] = &[
    EventFieldSpec {
        name: "senderAddress",
        size: 32,
        little_endian: false,
    },
    EventFieldSpec {
        name: "senderReencryptedTransferAmount",
        size: 32,
        little_endian: false,
    },
    EventFieldSpec {
        name: "senderReencryptedTransferAmountNonce",
        size: 16,
        little_endian: true,
    },
    EventFieldSpec {
        name: "receiverAddress",
        size: 32,
        little_endian: false,
    },
    EventFieldSpec {
        name: "receiverReencryptedTransferAmount",
        size: 32,
        little_endian: false,
    },
    EventFieldSpec {
        name: "receiverReencryptedTransferAmountNonce",
        size: 16,
        little_endian: true,
    },
    EventFieldSpec {
        name: "mint",
        size: 32,
        little_endian: false,
    },
];

pub const TRANSFER_BETWEEN_ACCOUNTS_CB: &EventSpec = &EventSpec {
    name: "TransferAmountBetweenTokenAccountsCallbackEvent",
    discriminator: &[83, 183, 5, 92, 116, 108, 230, 143],
    fields: TRANSFER_BETWEEN_ACCOUNTS_CB_FIELDS,
    total_size: 192,
};

pub const EVENT_SPECS: &[&EventSpec] = &[
    TRANSFER_BETWEEN_ACCOUNTS_CB,
    // add the rest here similarly
];

// Optional: map a parsed event into a Commitment, if relevant
pub trait EventToCommitment {
    fn to_commitment(&self) -> Option<Commitment>;
}

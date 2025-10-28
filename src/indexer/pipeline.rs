use crate::errors::IndexerResult;
use crate::storage::merkle_service::MerkleTreeService;
use serde_json::Value;

use super::events::{EventRegistry, EVENT_SPECS};
use super::serializers::SerializerRegistry;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;

pub struct IndexerPipeline {
    registry: SerializerRegistry,
    merkle: MerkleTreeService,
    program_id: String, // Filter events for this program
    events: EventRegistry,
}

impl IndexerPipeline {
    pub fn new(
        registry: SerializerRegistry,
        merkle: MerkleTreeService,
        program_id: String,
    ) -> Self {
        Self {
            registry,
            merkle,
            program_id,
            events: EventRegistry::new(EVENT_SPECS),
        }
    }

    pub fn handle_event(&mut self, evt: Value) -> IndexerResult<()> {
        // Laserstream format:
        // result: {
        //   transaction: { signature, slot, meta: { logMessages: [...] } },
        //   slot
        // }

        let tx_meta = evt
            .get("result")
            .and_then(|r| r.get("transaction"))
            .and_then(|tx| tx.get("meta"));

        if tx_meta.is_none() {
            return Ok(());
        }

        // Extract log messages (events are emitted here)
        if let Some(logs) = tx_meta
            .and_then(|meta| meta.get("logMessages"))
            .and_then(|logs| logs.as_array())
        {
            self.process_logs(logs)?;
        }

        Ok(())
    }

    fn process_logs(&mut self, logs: &[Value]) -> IndexerResult<()> {
        // Look for our program's event format: "Program data: <base64_data>"
        for log in logs {
            if let Some(log_str) = log.as_str() {
                // Look for our event marker
                if let Some(event_data) = log_str.strip_prefix("Program data: ") {
                    if let Some(event_data_trimmed) = event_data.strip_prefix(&self.program_id) {
                        // Decode the event data from base64
                        match BASE64_STANDARD.decode(event_data_trimmed.trim()) {
                            Ok(bytes) => {
                                log::debug!("decoded event bytes: {} bytes", bytes.len());
                                self.process_event_bytes(&bytes)?;
                            }
                            Err(e) => {
                                log::warn!("failed to decode base64 event data: {e}");
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn process_event_bytes(&mut self, bytes: &[u8]) -> IndexerResult<()> {
        // First, try identify against declarative event specs
        if let Some(parsed) = self.events.parse(bytes)? {
            log::info!("identified event: {}", parsed.spec.name);
            // If you want to route some events directly to commitments, implement conversion here
            // Fallback to registry-based parsing for commitment extraction
        }

        // Try to deserialize into a Commitment via registry
        match self.registry.parse(bytes) {
            Ok(Some(commitment)) => {
                log::info!("deserialized commitment, inserting to tree");
                self.merkle.insert_commitment(&commitment)?;
                self.merkle.save()?;
                Ok(())
            }
            Ok(None) => {
                log::debug!("no matching serializer for event bytes");
                Ok(())
            }
            Err(e) => {
                log::warn!("failed to parse event bytes: {e}");
                Ok(())
            }
        }
    }
}

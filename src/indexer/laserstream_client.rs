use anyhow::Result;
use futures_util::StreamExt;
use helius_laserstream::{
    grpc::{CommitmentLevel, SubscribeRequest, SubscribeRequestFilterTransactions},
    subscribe, LaserstreamConfig,
};
use serde_json::Value;

#[derive(Clone, Debug)]
pub struct LaserstreamConfigWrapper {
    pub endpoint: String,
    pub api_key: String,
    pub program_ids: Vec<String>,
}

pub struct LaserstreamEvent {
    pub value: Value,
}

pub struct LaserstreamClient {
    config: LaserstreamConfigWrapper,
}

impl LaserstreamClient {
    pub fn new(config: LaserstreamConfigWrapper) -> Self {
        Self { config }
    }

    pub async fn run<F>(&self, mut on_event: F) -> Result<()>
    where
        F: FnMut(LaserstreamEvent) + Send + 'static,
    {
        // Build Laserstream config
        let ls_config =
            LaserstreamConfig::new(self.config.endpoint.clone(), self.config.api_key.clone());

        // Build subscription request for transactions
        let request = SubscribeRequest {
            transactions: {
                let mut map = std::collections::HashMap::new();
                for (idx, program_id) in self.config.program_ids.iter().enumerate() {
                    map.insert(
                        format!("program-{}", idx),
                        SubscribeRequestFilterTransactions {
                            account_include: vec![program_id.clone()],
                            vote: Some(false),
                            failed: Some(false),
                            ..Default::default()
                        },
                    );
                }
                map
            },
            commitment: Some(CommitmentLevel::Confirmed as i32),
            ..Default::default()
        };

        log::info!(
            "Connecting to Laserstream endpoint: {}",
            self.config.endpoint
        );

        // Subscribe and get stream
        let (stream, _handle) = subscribe(ls_config, request);
        tokio::pin!(stream);

        // Process updates
        while let Some(result) = stream.next().await {
            match result {
                Ok(update) => {
                    // Access the update_oneof field which contains the actual update data
                    match &update.update_oneof {
                        // Serialize transaction updates to JSON and forward
                        Some(
                            helius_laserstream::grpc::subscribe_update::UpdateOneof::Transaction(
                                tx,
                            ),
                        ) => {
                            // Build a minimal JSON representation without requiring Serialize on SDK types
                            let json = serde_json::json!({
                                "type": "transaction",
                                "debug": format!("{:?}", tx),
                            });
                            on_event(LaserstreamEvent { value: json });
                        }
                        _ => {
                            log::debug!("Received non-transaction update");
                        }
                    }
                }
                Err(e) => {
                    log::error!("Laserstream error: {}", e);
                    return Err(anyhow::anyhow!("Laserstream error: {}", e));
                }
            }
        }

        Ok(())
    }
}

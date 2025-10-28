use crate::errors::IndexerResult;
use crate::indexer::laserstream_client::{LaserstreamClient, LaserstreamConfigWrapper};
use crate::indexer::pipeline::IndexerPipeline;
use crate::indexer::serializers::SerializerRegistry;
use crate::storage::merkle_service::MerkleTreeService;

pub struct IndexService {
    pipeline: IndexerPipeline,
    client: LaserstreamClient,
}

impl IndexService {
    pub fn new(
        data_dir: &str,
        depth: Option<usize>,
        laserstream_endpoint: String,
        laserstream_api_key: String,
        program_ids: Vec<String>,
        registry: SerializerRegistry,
    ) -> IndexerResult<Self> {
        let merkle = MerkleTreeService::new(data_dir, depth)?; // creates or opens existing tree
                                                               // Use first program ID for filtering events
        let program_id = program_ids
            .first()
            .cloned()
            .unwrap_or_else(|| "".to_string());
        let pipeline = IndexerPipeline::new(registry, merkle, program_id);
        let client = LaserstreamClient::new(LaserstreamConfigWrapper {
            endpoint: laserstream_endpoint,
            api_key: laserstream_api_key,
            program_ids,
        });
        Ok(Self { pipeline, client })
    }

    pub async fn run(self) -> IndexerResult<()> {
        let mut pipeline = self.pipeline;
        let result = self
            .client
            .run(move |evt| {
                if let Err(e) = pipeline.handle_event(evt.value) {
                    log::error!("pipeline error: {e}");
                }
            })
            .await;
        if let Err(e) = result {
            return Err(crate::errors::IndexerError::StorageError(format!(
                "indexer runtime error: {e}"
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum SerializationFormat {
    /// Binary format (fastest)
    Bincode,
    /// MessagePack format (portable)
    MessagePack,
    /// Postcard format (smallest)
    Postcard,
}

impl Default for SerializationFormat {
    fn default() -> Self {
        SerializationFormat::Bincode
    }
}

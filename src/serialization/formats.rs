#[derive(Debug, Clone, Default)]
pub enum SerializationFormat {
    /// Binary format (fastest)
    #[default]
    Bincode,
    /// MessagePack format (portable)
    MessagePack,
    /// Postcard format (smallest)
    Postcard,
}

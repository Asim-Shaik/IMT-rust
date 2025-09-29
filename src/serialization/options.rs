use super::SerializationFormat;

/// Configuration options for serialization
#[derive(Debug, Clone)]
pub struct SerializationOptions {
    /// Serialization format to use
    pub format: SerializationFormat,
    /// Whether to compress the serialized data
    pub compress: bool,
    /// Compression level (0-9, where 9 is highest compression)
    pub compression_level: u32,
}

impl SerializationOptions {
    /// Create new serialization options
    pub fn new(format: SerializationFormat, compress: bool, compression_level: u32) -> Self {
        Self {
            format,
            compress,
            compression_level: compression_level.min(9),
        }
    }

    /// Create options for fastest serialization
    pub fn fastest() -> Self {
        Self {
            format: SerializationFormat::Bincode,
            compress: false,
            compression_level: 0,
        }
    }

    /// Create options for smallest size
    pub fn smallest() -> Self {
        Self {
            format: SerializationFormat::Postcard,
            compress: true,
            compression_level: 9,
        }
    }

    /// Create options for balanced performance/size
    pub fn balanced() -> Self {
        Self {
            format: SerializationFormat::Bincode,
            compress: true,
            compression_level: 6,
        }
    }
}

impl Default for SerializationOptions {
    fn default() -> Self {
        Self::balanced()
    }
}

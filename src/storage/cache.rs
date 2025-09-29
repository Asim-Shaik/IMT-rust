use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

/// LRU cache for frequently accessed pages
#[derive(Debug)]
pub struct PageCache {
    pages: HashMap<usize, Arc<RwLock<Vec<u8>>>>,
    max_size: usize,
    access_order: Vec<usize>,
}

impl PageCache {
    /// Create a new page cache with the specified maximum number of pages
    pub fn new(max_pages: usize) -> Self {
        Self {
            pages: HashMap::new(),
            max_size: max_pages,
            access_order: Vec::new(),
        }
    }

    /// Get a page from the cache, updating its access time
    pub fn get(&mut self, page_id: usize) -> Option<Arc<RwLock<Vec<u8>>>> {
        if let Some(page) = self.pages.get(&page_id) {
            // Move to end (most recently used)
            self.access_order.retain(|&id| id != page_id);
            self.access_order.push(page_id);
            Some(page.clone())
        } else {
            None
        }
    }

    /// Insert a page into the cache, potentially evicting old pages
    pub fn insert(&mut self, page_id: usize, page_data: Vec<u8>) -> Arc<RwLock<Vec<u8>>> {
        // Evict least recently used pages if necessary
        while self.pages.len() >= self.max_size && !self.access_order.is_empty() {
            let lru_page = self.access_order.remove(0);
            self.pages.remove(&lru_page);
        }

        let page = Arc::new(RwLock::new(page_data));
        self.pages.insert(page_id, page.clone());
        self.access_order.push(page_id);
        page
    }

    /// Remove a page from the cache
    pub fn remove(&mut self, page_id: usize) -> Option<Arc<RwLock<Vec<u8>>>> {
        self.access_order.retain(|&id| id != page_id);
        self.pages.remove(&page_id)
    }

    /// Clear all pages from the cache
    pub fn clear(&mut self) {
        self.pages.clear();
        self.access_order.clear();
    }

    /// Get the current number of cached pages
    pub fn len(&self) -> usize {
        self.pages.len()
    }

    /// Check if the cache is empty
    pub fn is_empty(&self) -> bool {
        self.pages.is_empty()
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            current_pages: self.pages.len(),
            max_pages: self.max_size,
            utilization: self.pages.len() as f64 / self.max_size as f64,
        }
    }

    /// Get all pages for iteration (used internally)
    pub fn pages(&self) -> &HashMap<usize, Arc<RwLock<Vec<u8>>>> {
        &self.pages
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub current_pages: usize,
    pub max_pages: usize,
    pub utilization: f64,
}

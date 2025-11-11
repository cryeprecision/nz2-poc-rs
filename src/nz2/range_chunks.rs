use std::{cmp, ops};

#[derive(Clone)]
pub struct RangeChunks {
    pub current: u64,
    pub end: u64,
    pub chunk_size: u64,
}

impl RangeChunks {
    pub fn new(start: u64, end: u64, chunk_size: u64) -> Self {
        assert!(start <= end, "start must be less than or equal to end");
        assert!(chunk_size > 0, "chunk_size must be greater than 0");
        Self {
            current: start,
            end,
            chunk_size,
        }
    }
}

impl Iterator for RangeChunks {
    type Item = ops::Range<u64>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.end {
            return None;
        }

        let start = self.current;
        let end = cmp::min(start + self.chunk_size, self.end);
        self.current = end;

        Some(start..end)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = (self.end - self.current).div_ceil(self.chunk_size);
        (remaining as usize, Some(remaining as usize))
    }
}

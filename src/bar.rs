/// A simple wrapper around indicatif::MultiProgress to easily enable/disable progress bars.
pub struct MultiProgress {
    bars: indicatif::MultiProgress,
}

impl MultiProgress {
    pub fn new(disabled: bool) -> Self {
        Self {
            bars: indicatif::MultiProgress::with_draw_target(if disabled {
                indicatif::ProgressDrawTarget::hidden()
            } else {
                indicatif::ProgressDrawTarget::stderr()
            }),
        }
    }

    pub fn add(&self, bar: indicatif::ProgressBar) -> indicatif::ProgressBar {
        self.bars.add(bar)
    }

    pub fn remove(&self, bar: &indicatif::ProgressBar) {
        self.bars.remove(bar)
    }

    pub fn suspend<F, R>(&self, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        self.bars.suspend(f)
    }
}

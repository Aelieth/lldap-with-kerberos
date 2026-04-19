#[derive(Default, Clone, PartialEq)]
pub struct TableBulkSelection<T: Clone + PartialEq> {
    pub selected: Vec<T>,
}

impl<T: Clone + PartialEq> TableBulkSelection<T> {
    pub fn toggle(&mut self, item: T) {
        if self.selected.contains(&item) {
            self.selected.retain(|i| i != &item);
        } else {
            self.selected.push(item);
        }
    }

    pub fn toggle_all(&mut self, all_filtered: &[T]) {
        if self.selected.len() == all_filtered.len() && !all_filtered.is_empty() {
            self.selected.clear();
        } else {
            self.selected = all_filtered.to_vec();
        }
    }

    pub fn clear(&mut self) {
        self.selected.clear();
    }

    pub fn is_selected(&self, item: &T) -> bool {
        self.selected.contains(item)
    }

    pub fn all_selected(&self, filtered: &[T]) -> bool {
        !filtered.is_empty() && filtered.iter().all(|item| self.is_selected(item))
    }
}

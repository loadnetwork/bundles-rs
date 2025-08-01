use crate::data_item::DataItem;

#[derive(Debug, Clone)]
pub struct Bundle {
    pub items: Vec<DataItem>,
}

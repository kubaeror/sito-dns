pub fn production(value: u32) -> u32 {
    #[cfg(test)]
    match value {
        0 => 0,
        _ => 1,
    }
}

pub fn after_block(value: u32) -> u32 {
    value
}

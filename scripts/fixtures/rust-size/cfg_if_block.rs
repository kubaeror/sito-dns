pub fn production() -> u32 {
    #[cfg(test)]
    if true {
        return 2;
    }
    1
}

pub fn after_block() -> u32 {
    3
}

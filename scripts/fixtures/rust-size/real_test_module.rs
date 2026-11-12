pub fn production() -> u32 {
    1
}

#[cfg(test)]
mod tests {
    #[test]
    fn works() {
        assert_eq!(super::production(), 1);
    }
}

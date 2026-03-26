// Helper function to zero-pad bytes to a specific length
// This matches Go's zeroPadBytes function exactly
pub fn zero_pad_bytes(m: &[u8], outlen: usize) -> Vec<u8> {
    if m.len() < outlen {
        let padlen = outlen - m.len();
        let mut out = vec![0u8; padlen];
        out.extend_from_slice(m);
        out
    } else {
        m.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_pad_bytes() {
        // Test case 1: input shorter than output length
        let input = vec![1, 2, 3];
        let result = zero_pad_bytes(&input, 6);
        assert_eq!(result, vec![0, 0, 0, 1, 2, 3]);

        // Test case 2: input equal to output length
        let input = vec![1, 2, 3];
        let result = zero_pad_bytes(&input, 3);
        assert_eq!(result, vec![1, 2, 3]);

        // Test case 3: input longer than output length
        let input = vec![1, 2, 3, 4, 5];
        let result = zero_pad_bytes(&input, 3);
        assert_eq!(result, vec![1, 2, 3, 4, 5]);

        // Test case 4: empty input
        let input = vec![];
        let result = zero_pad_bytes(&input, 4);
        assert_eq!(result, vec![0, 0, 0, 0]);

        // Test case 5: zero output length
        let input = vec![1, 2, 3];
        let result = zero_pad_bytes(&input, 0);
        assert_eq!(result, vec![1, 2, 3]);
    }
} 
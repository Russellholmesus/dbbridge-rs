use super::byte_window::ByteWindow;

#[test]
fn spec_segments_match_read_range() {
    let w = ByteWindow::new(10, 1 << 20);
    w.set_chunk_size(5);
    let src = b"abcdefghijklmnopqrstuvwxyz";
    w.append(10, &src[..13]).unwrap();
    w.append_owned(23, src[13..].to_vec()).unwrap();
    w.acknowledge(12); // partial ACK inside the first block
    for off in 12u64..=36 {
        for limit in 0usize..=30 {
            let (want, want_next, _) = w.read_range(off, limit).expect("read_range");
            let (segs, next) = w
                .segments(off, limit)
                .unwrap_or_else(|| panic!("off {off} limit {limit}: segments refused"));
            assert_eq!(next, want_next, "off {off} limit {limit}");
            assert_eq!(segs.concat(), want, "off {off} limit {limit}");
        }
    }
    assert!(w.segments(11, 4).is_none(), "acknowledged offset accepted");
    let (segs, _) = w.segments(20, 10).unwrap();
    w.acknowledge(36);
    w.reset();
    assert_eq!(segs.concat(), b"klmnopqrst", "view changed after release");
}

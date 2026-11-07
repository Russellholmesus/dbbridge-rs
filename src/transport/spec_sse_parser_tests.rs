use super::sse_carrier::{SseEvent, SseEventReader, SseStep};
use std::io::{Read, Write};
use std::time::Duration;

struct StepConn {
    data: Vec<u8>,
    pos: usize,
    step: usize,
}

impl Read for StepConn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = buf.len().min(self.step).min(self.data.len() - self.pos);
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

impl Write for StepConn {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl crate::net::Conn for StepConn {
    fn set_read_timeout(&self, _: Option<Duration>) -> std::io::Result<()> {
        Ok(())
    }
    fn set_write_timeout(&self, _: Option<Duration>) -> std::io::Result<()> {
        Ok(())
    }
    fn try_clone(&self) -> std::io::Result<Box<dyn crate::net::Conn>> {
        Err(std::io::Error::other("not cloneable"))
    }
    fn shutdown_write(&self) -> std::io::Result<()> {
        Ok(())
    }
    fn shutdown_both(&self) -> std::io::Result<()> {
        Ok(())
    }
    fn describe(&self) -> String {
        "step".into()
    }
}

fn test_sub(input: &str, step: usize) -> SseEventReader {
    let conn = crate::net::BufferedConn::new(StepConn {
        data: input.as_bytes().to_vec(),
        pos: 0,
        step,
    });
    let body = crate::net::http1::BodyReader::new(conn, &[]);
    SseEventReader::new(body, 1024, 1)
}

#[test]
fn spec_sse_parser_whatwg() {
    let w = |event: &str, id: &str, data: &str| SseEvent {
        event: event.into(),
        id: id.into(),
        data: data.into(),
    };
    let ok: Vec<(&str, &str, Vec<SseEvent>)> = vec![
        (
            "multi-line data",
            "event: x\ndata: a\ndata: b\n\n",
            vec![w("x", "", "a\nb")],
        ),
        (
            "retry ignored",
            "retry: 1000\nevent: x\ndata: a\n\n",
            vec![w("x", "", "a")],
        ),
        (
            "unknown ignored",
            "event: x\nfoo: bar\ndata: a\n\n",
            vec![w("x", "", "a")],
        ),
        ("CR endings", "event: x\rdata: a\r\r", vec![w("x", "", "a")]),
        (
            "CRLF endings",
            "event: x\r\nid: 7\r\ndata: a\r\n\r\n",
            vec![w("x", "7", "a")],
        ),
        (
            "mixed endings",
            "event: x\rdata: a\r\r\nevent: y\ndata: b\r\n\nevent: z\r\ndata: c\r\r",
            vec![w("x", "", "a"), w("y", "", "b"), w("z", "", "c")],
        ),
        (
            "field without colon",
            "event: x\ndata: a\nid\n\n",
            vec![w("x", "", "a")],
        ),
        ("bare data", "event: x\ndata\n\n", vec![w("x", "", "")]),
        (
            "one space stripped",
            "event:x\ndata:  a\n\n",
            vec![w("x", "", " a")],
        ),
        (
            "value with colon",
            "event: x\ndata: a:b\n\n",
            vec![w("x", "", "a:b")],
        ),
        (
            "no data skipped",
            "event: x\n\nevent: y\ndata: b\n\n",
            vec![w("y", "", "b")],
        ),
        (
            "comment mid-event",
            "event: x\n: hi\ndata: a\n\n",
            vec![w("x", "", "a")],
        ),
    ];
    for (name, input, want) in &ok {
        for slow in [false, true] {
            let mut s = test_sub(input, if slow { 1 } else { usize::MAX });
            for (i, wv) in want.iter().enumerate() {
                match s.next_event() {
                    Ok(SseStep::Event(ev)) => assert_eq!(
                        &ev, wv,
                        "{name} (slow={slow}) event {i}: got {ev:?} want {wv:?}"
                    ),
                    Ok(SseStep::Idle) => panic!("{name} (slow={slow}) event {i}: idle"),
                    Ok(SseStep::Eof) => panic!("{name} (slow={slow}) event {i}: EOF"),
                    Err(e) => panic!("{name} (slow={slow}) event {i}: {e}"),
                }
            }
            match s.next_event() {
                Ok(SseStep::Eof) => {}
                Ok(SseStep::Event(ev)) => {
                    panic!("{name} (slow={slow}): trailing input: event {ev:?}")
                }
                Ok(SseStep::Idle) => panic!("{name} (slow={slow}): trailing input: idle"),
                Err(e) => panic!("{name} (slow={slow}): trailing input: {e}"),
            }
        }
    }
    let bad: Vec<(&str, String)> = vec![
        ("data without event", "data: a\n\n".into()),
        ("duplicate event", "event: x\nevent: y\ndata: a\n\n".into()),
        ("duplicate id", "event: x\nid: 1\nid: 2\ndata: a\n\n".into()),
        (
            "too many lines",
            format!("event: x\n{}\n", "data: a\n".repeat(64)),
        ),
        (
            "joined too large",
            format!(
                "event: x\n{}\n",
                format!("data: {}\n", "a".repeat(1000)).repeat(20)
            ),
        ),
        (
            "line too large CR",
            format!("event: x\rdata: {}\r\r", "a".repeat(20 << 10)),
        ),
        (
            "comment too large",
            format!(":{}\n\nevent: x\ndata: a\n\n", "a".repeat(20 << 10)),
        ),
    ];
    for (name, input) in &bad {
        match test_sub(input, usize::MAX).next_event() {
            Err(e) => assert_eq!(
                e.code,
                crate::wire::ERR_BAD_FRAME,
                "{name}: err={e}, want ErrProtocol"
            ),
            Ok(SseStep::Event(ev)) => panic!("{name}: got event {ev:?}, want ErrProtocol"),
            Ok(_) => panic!("{name}: no error, want ErrProtocol"),
        }
    }
}

//! End-to-end IPC tests over a real named pipe.
//!
//! These exist because a bug in the accept loop is invisible to unit tests of the framing and
//! authorization: the pipe accepts the connection and then closes it, which looks like a
//! transport error to the client and like nothing at all on the server. Only an actual round
//! trip catches it.

use super::*;

/// A unique pipe name so parallel tests cannot collide with each other or a real service.
fn unique_pipe(tag: &str) -> String {
    format!(
        "guardian-ipc-it-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    )
}

/// Run a server accept/serve loop against a named pipe, on its own thread.
fn spawn_server(
    pipe_name: String,
    handler: Arc<dyn RequestHandler>,
    shutdown: Arc<AtomicBool>,
    connections: usize,
) -> std::thread::JoinHandle<u32> {
    std::thread::spawn(move || {
        // The same spare-instance pattern the production loop uses: arm the next instance before
        // serving the current one, so a client arriving during service finds somebody listening.
        let mut listener = match PipeServer::create(&pipe_name) {
            Ok(s) => s,
            Err(e) => panic!("could not create the test pipe: {e}"),
        };

        let mut served = 0u32;
        let mut accepted = 0usize;
        while accepted < connections && !shutdown.load(Ordering::Relaxed) {
            match listener.wait_for_client(2000) {
                Ok(true) => {}
                Ok(false) => continue,
                Err(e) => panic!("accept failed: {e}"),
            }
            accepted += 1;

            let mut serving = listener;
            listener = PipeServer::create(&pipe_name).expect("create the next instance");

            match serve_connection(
                &mut serving,
                handler.as_ref(),
                Principal::Administrator,
                &shutdown,
            ) {
                Ok(n) => {
                    served += n;
                    serving.disconnect();
                }
                Err(e) => {
                    serving.disconnect();
                    panic!("serve failed: {e}");
                }
            }
        }
        served
    })
}

fn test_handler() -> Arc<dyn RequestHandler> {
    let state = Arc::new(RwLock::new(ServiceState::initial(
        "boot-1".into(),
        1_000_000,
        "0.1.0".into(),
    )));
    Arc::new(ReadOnlyHandler::new(state))
}

/// Send one request over a fresh connection.
fn call_once(pipe_name: &str, request: &Request) -> Response {
    let mut client = PipeClient::connect(pipe_name, 5000).expect("client must connect");
    let payload = serde_json::to_vec(request).expect("encode");
    write_frame(&mut client, &payload).expect("write must succeed");
    let frame = read_frame(&mut client)
        .expect("read must succeed")
        .expect("a response frame must arrive");
    serde_json::from_slice(&frame).expect("decode")
}

#[test]
fn a_single_request_gets_a_reply() {
    // The property the whole IPC surface depends on. A client that connects and is immediately
    // closed is the failure this guards against.
    let pipe = unique_pipe("single");
    let shutdown = Arc::new(AtomicBool::new(false));
    let handle = spawn_server(pipe.clone(), test_handler(), Arc::clone(&shutdown), 1);

    match call_once(&pipe, &Request::GetStatus) {
        Response::Status { snapshot: s } => assert_eq!(s.boot_id, "boot-1"),
        other => panic!("unexpected response: {other:?}"),
    }

    assert_eq!(handle.join().expect("the server thread must not panic"), 1);
}

#[test]
fn several_sequential_requests_all_get_replies() {
    // Creating a new pipe instance per accept would let a client land on an abandoned instance and
    // be closed. Three sequential requests over one instance prove the instance is reused.
    let pipe = unique_pipe("sequential");
    let shutdown = Arc::new(AtomicBool::new(false));
    let handle = spawn_server(pipe.clone(), test_handler(), Arc::clone(&shutdown), 3);

    for i in 0..3 {
        let response = call_once(&pipe, &Request::GetIncidents { limit: 5 });
        assert!(
            matches!(response, Response::Incidents { .. }),
            "request {i} got {response:?}"
        );
    }

    assert_eq!(handle.join().expect("the server thread must not panic"), 3);
}

#[test]
fn a_malformed_request_is_replied_to_rather_than_dropped() {
    // A hostile or buggy client must get an answer, not a silently closed pipe, so it can report
    // what went wrong.
    let pipe = unique_pipe("malformed");
    let shutdown = Arc::new(AtomicBool::new(false));
    let handle = spawn_server(pipe.clone(), test_handler(), Arc::clone(&shutdown), 1);

    let mut client = PipeClient::connect(&pipe, 5000).expect("connect");
    write_frame(&mut client, b"this is not json").expect("write");
    let frame = read_frame(&mut client)
        .expect("read")
        .expect("a reply must arrive even for a malformed request");
    let response: Response = serde_json::from_slice(&frame).expect("decode");
    assert!(
        matches!(response, Response::Error { .. }),
        "expected an invalid-request error, got {response:?}"
    );
    let _ = handle.join();
}

#[test]
fn an_oversized_frame_closes_the_connection_without_taking_the_server_down() {
    // A hostile client announcing a huge frame must be rejected, and the server must survive to
    // serve the next client.
    let pipe = unique_pipe("oversized");
    let shutdown = Arc::new(AtomicBool::new(false));
    let handle = spawn_server(pipe.clone(), test_handler(), Arc::clone(&shutdown), 2);

    {
        let mut client = PipeClient::connect(&pipe, 5000).expect("connect");
        // A length prefix far above the frame cap, then nothing.
        let mut frame = Vec::new();
        frame.extend_from_slice(&(MAX_FRAME_LEN + 1).to_le_bytes());
        client
            .write_all(&frame)
            .expect("the length prefix is accepted");
        // Closing without sending the body is exactly what the server must survive.
    }

    // The next client must still be served.
    match call_once(&pipe, &Request::GetStatus) {
        Response::Status { .. } => {}
        other => panic!("the server must survive a hostile frame, got {other:?}"),
    }

    let _ = handle.join();
}

#[test]
fn a_second_connection_after_a_served_one_is_accepted() {
    // Isolates the reuse path: connect, disconnect, connect again. The failure this pins down is
    // that the second client is accepted by an instance nobody is serving.
    let pipe = unique_pipe("reuse");
    let shutdown = Arc::new(AtomicBool::new(false));
    let handler = test_handler();

    let pipe_for_server = pipe.clone();
    let shutdown_for_server = Arc::clone(&shutdown);
    let server = std::thread::spawn(move || {
        let mut listener = PipeServer::create(&pipe_for_server).expect("create");

        // Serve exactly two connections, arming the next instance before each serve.
        let mut results = Vec::new();
        for _ in 0..2 {
            let accepted = listener.wait_for_client(3000).expect("accept");
            results.push(accepted);

            let mut serving = listener;
            listener = PipeServer::create(&pipe_for_server).expect("create next");

            let served = serve_connection(
                &mut serving,
                handler.as_ref(),
                Principal::Administrator,
                &shutdown_for_server,
            );
            results.push(served.is_ok());
            serving.disconnect();
        }
        results
    });

    // First connection.
    let first = call_once(&pipe, &Request::GetStatus);
    assert!(
        matches!(first, Response::Status { .. }),
        "first got {first:?}"
    );

    // Second connection, after the first was fully served.
    let second = call_once(&pipe, &Request::GetStatus);
    assert!(
        matches!(second, Response::Status { .. }),
        "second got {second:?}"
    );

    let results = server.join().expect("server thread");
    assert!(results[0], "the first accept must succeed");
    assert!(results[2], "the second accept must succeed");
}

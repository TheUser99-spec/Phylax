use agentguard_store::Store;
use std::net::SocketAddr;
use std::sync::Arc;

mod routes;

pub struct WebServer {
    store: Store,
    port: u16,
}

impl WebServer {
    pub fn new(store: Store, port: u16) -> Self {
        Self { store, port }
    }

    pub async fn run(self) {
        let app_state = Arc::new(AppState {
            store: self.store,
        });

        let app = routes::build_router(app_state);

        let addr = SocketAddr::from(([127, 0, 0, 1], self.port));
        println!("[web] Phylax Dashboard → http://{}", addr);

        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[web] Cannot bind port {}: {e}", self.port);
                return;
            }
        };

        if let Err(e) = axum::serve(listener, app).await {
            eprintln!("[web] Server error: {e}");
        }
    }
}

pub struct AppState {
    pub store: Store,
}

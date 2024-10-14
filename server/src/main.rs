use axum::{
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Deserialize)]
struct RegisterDeviceBody {
    diddoc: String,
}

#[derive(Serialize)]
struct RegisterResult {
    message: String,
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(root))
        .route("/register_device", post(register_device));

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    println!("Listening on: {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

async fn root() -> String {
    "Hello, World!".to_string()
}

async fn register_device(
    Json(register_device_body): Json<RegisterDeviceBody>,
) -> (StatusCode, Json<RegisterResult>) {
    println!("DIDDoc: {}", register_device_body.diddoc);

    let result = Command::new("./add_client/build/add_client")
        .arg(register_device_body.diddoc)
        .output()
        .expect("failed to execute process")
        .stdout;

    println!("Result: {:?}", result);

    let result = RegisterResult {
        message: "Device registered".to_string(),
    };
    (StatusCode::CREATED, Json(result))
}

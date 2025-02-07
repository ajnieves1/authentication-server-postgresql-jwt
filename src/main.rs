// Importing necessary crates and modules
use auth::{with_auth, Role}; // Importing authentication helpers (auth module)
use error::Error::*; // Importing errors from the error module
use serde::{Deserialize, Serialize}; // Importing serde for serialization and deserialization
use std::collections::HashMap; // Importing HashMap for storing data in memory (never ended up using this)
use std::sync::Arc; // Importing Arc for reference counted memory sharing across threads
use warp::{reject, reply, Filter, Rejection, Reply}; // Warp for HTTP server and routing
use sqlx::PgPool; // SQLx for PostgreSQL connection pool
use dotenv::dotenv; // Importing dotenv for reading environment variables from a `.env` file
use std::env; // Environment variable access
use bcrypt::{verify}; // Importing bcrypt crate for password verification
use std::convert::Infallible; // Importing Infallible type for warp filters

// Declaring the modules
mod auth;
mod error;

// Result type alias for custom error handling
type Result<T> = std::result::Result<T, error::Error>;
// WebResult type alias for warp's error handling
type WebResult<T> = std::result::Result<T, Rejection>;
// Users type alias for a shared reference-counted HashMap
type Users = Arc<HashMap<String, User>>;

// Defining the User struct to represent user data
#[derive(Clone)] // Making the struct cloneable
pub struct User {
    pub uid: String, // User's unique ID
    pub email: String, // User's email address
    pub password: String, // User's hashed password
    pub role: String, // User's role (e.g., "Admin", "User")
}

// Defining the LoginRequest struct to handle incoming login requests
#[derive(Deserialize)] // Deriving Deserialize to parse JSON into this struct
pub struct LoginRequest {
    pub email: String, // User's email address for login
    pub password: String, // User's password for login
}

// Defining the LoginResponse struct to handle outgoing login responses
#[derive(Serialize)] // Deriving Serialize to convert this struct to JSON
pub struct LoginResponse {
    pub token: String, // JWT token generated for the user
}

// Defining the RegisterRequest struct to handle incoming registration requests
#[derive(Deserialize)] // Deriving Deserialize for JSON parsing
struct RegisterRequest {
    email: String, // User's email for registration
    password: String, // User's password for registration
    role: String, // User's role (e.g., "Admin" or "User")
}

#[tokio::main] // Using the Tokio runtime for asynchronous execution
async fn main() {
    dotenv().ok(); // Load environment variables from the .env file
    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set"); // Get the database URL from environment
    let pool = PgPool::connect(&db_url).await.expect("Failed to connect to DB"); // Establish a connection pool to the PostgreSQL database
    let pool = Arc::new(pool); // Wrap the pool in an Arc for shared ownership

    // Define the register route
    let register_route = warp::path("register") // Match the "/register" URL path
        .and(warp::post()) // Only accept POST requests
        .and(with_db(pool.clone())) // Add database connection as a filter
        .and(warp::body::json()) // Parse the request body as JSON
        .and_then(register_handler); // Use the `register_handler` function to process the request

    // Define the login route
    let login_route = warp::path("login") // Match the "/login" URL path
        .and(warp::post()) // Only accept POST requests
        .and(with_db(pool.clone())) // Add database connection as a filter
        .and(warp::body::json()) // Parse the request body as JSON
        .and_then(login_handler); // Use the `login_handler` function to process the request

    // Define the user route, requiring User-level authentication
    let user_route = warp::path("user") // Match the "/user" URL path
        .and(with_auth(auth::Role::User)) // Only allow users with "User" role to access this route
        .and_then(user_handler); // Use the `user_handler` function to process the request

    // Define the admin route, requiring Admin-level authentication
    let admin_route = warp::path("admin") // Match the "/admin" URL path
        .and(with_auth(auth::Role::Admin)) // Only allow users with "Admin" role to access this route
        .and_then(admin_handler); // Use the `admin_handler` function to process the request

    // Combine all routes into one set
    let routes = register_route
        .or(login_route) // Allow both the register and login routes
        .or(user_route) // Allow the user route
        .or(admin_route) // Allow the admin route
        .recover(error::handle_rejection); // Handle any errors that occur

    // Start the server, listening on localhost at port 8000
    warp::serve(routes).run(([127, 0, 0, 1], 8000)).await;
}

// Helper function to inject the database connection pool into handlers
fn with_db(pool: Arc<PgPool>) -> impl Filter<Extract = (Arc<PgPool>,), Error = Infallible> + Clone {
    warp::any().map(move || pool.clone()) // Create a filter that clones the pool reference
}

// Register handler function to handle user registration
async fn register_handler(pool: Arc<PgPool>, body: RegisterRequest) -> WebResult<impl Reply> {
    let hashed_password = bcrypt::hash(&body.password, bcrypt::DEFAULT_COST) // Hash the provided password using bcrypt
        .map_err(|_| reject::custom(error::Error::JWTTokenCreationError))?; // Handle errors during hashing

    // Insert the new user into the database
    let result = sqlx::query_as::<_, (String,)>( // Query that returns the user's UID after insertion
        "INSERT INTO users (email, password, role) VALUES ($1, $2, $3) RETURNING uid"
    )
    .bind(&body.email) // Bind the email parameter
    .bind(&hashed_password) // Bind the hashed password parameter
    .bind(&body.role) // Bind the role parameter
    .fetch_one(&*pool) // Execute the query and fetch one result
    .await;
    
    // Handle the result of the insertion
    match result {
        Ok(record) => Ok(reply::json(&serde_json::json!({"uid": record.0}))), // If successful, return the user's UID
        Err(_) => Err(reject::custom(error::Error::WrongCredentialsError)), // If failed, reject with an error
    }
}

// Login handler function to authenticate users
pub async fn login_handler(pool: Arc<PgPool>, body: LoginRequest) -> WebResult<impl Reply> {
    // Query the database for the user by email
    let user = sqlx::query_as::<_, (String, String, String)>( // Query to fetch UID, password, and role
        "SELECT uid, password, role FROM users WHERE email = $1"
    )
    .bind(&body.email) // Bind the email parameter
    .fetch_optional(&*pool) // Fetch an optional result (user may not exist)
    .await
    .map_err(|_| reject::custom(error::Error::WrongCredentialsError))?; // Handle query error

    match user {
        // If user is found, verify the password and generate a JWT token
        Some((uid, password, role)) => {
            if verify(&body.password, &password).unwrap_or(false) { // Verify the password using bcrypt
                let token = auth::create_jwt(&uid, &auth::Role::from_str(&role)) // Create a JWT token
                    .map_err(|e| reject::custom(e))?; // Handle JWT creation errors
                Ok(reply::json(&LoginResponse { token })) // Return the JWT token in the response
            } else {
                Err(reject::custom(error::Error::WrongCredentialsError)) // If password is incorrect, reject
            }
        }
        None => Err(reject::custom(error::Error::WrongCredentialsError)), // If user not found, reject
    }
}

// User handler function for the "user" route
pub async fn user_handler(uid: String) -> WebResult<impl Reply> {
    Ok(format!("Hello User {}", uid)) // Return a greeting with the user's UID
}

// Admin handler function for the "admin" route
pub async fn admin_handler(uid: String) -> WebResult<impl Reply> {
    Ok(format!("Hello Admin {}", uid)) // Return a greeting with the admin's UID
}

// This function initializes a mock set of users (not used because it was annoying)
fn init_users() -> HashMap<String, User> {
    let mut map = HashMap::new(); // Create a new HashMap to store users
    map.insert(
        String::from("1"), // Key: user ID
        User {
            uid: String::from("1"),
            email: String::from("user@userland.com"),
            password: String::from("1234"),
            role: String::from("User"),
        },
    );
    map.insert(
        String::from("2"), // Key: admin ID
        User {
            uid: String::from("2"),
            email: String::from("admin@adminaty.com"),
            password: String::from("4321"),
            role: String::from("Admin"),
        },
    );
    map // Return the populated HashMap
}

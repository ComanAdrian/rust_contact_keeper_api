use warp::Filter;

use crate::filters::*;
use crate::models::{DeleteOptions, UpdateOptions};

#[tokio::main]
async fn main() {
    let db = db::connect().await;

    let api_register_user = warp::path!("api" / "register")
        .and(warp::post())
        .and(with_register_user())
        .and(with_db(db.clone()))
        .and_then(handlers::register_user);

    let api_auth_user = warp::path!("api" / "auth")
        .and(warp::post())
        .and(with_auth_user())
        // .and(with_contact_length_limit::<AuthUserRequest>())
        .and(with_db(db.clone()))
        .and_then(handlers::auth_user);

    let api_load_user = warp::path!("api" / "auth")
        .and(warp::get())
        .and(warp::header("x-auth-token"))
        .and(with_db(db.clone()))
        .and_then(handlers::load_user);

    let api_create_contact = warp::path!("api" / "contacts")
        .and(warp::post())
        .and(warp::header("x-auth-token"))
        .and(with_contact())
        .and(with_db(db.clone()))
        .and_then(handlers::create_contact);

    let api_delete_contact = warp::path!("api" / "contacts")
        .and(warp::delete())
        .and(warp::header("x-auth-token"))
        .and(warp::query::<DeleteOptions>())
        .and(with_db(db.clone()))
        .and_then(handlers::delete_contact);

    let api_update_contact = warp::path!("api" / "contacts")
        .and(warp::put())
        .and(warp::header("x-auth-token"))
        .and(warp::query::<UpdateOptions>())
        .and(with_contact())
        .and(with_db(db.clone()))
        .and_then(handlers::update_contact);

    let api_load_contacts = warp::path!("api" / "contacts")
        .and(warp::get())
        .and(warp::header("x-auth-token"))
        .and(with_db(db.clone()))
        .and_then(handlers::load_contacts);

    warp::serve(
        api_register_user
            .or(api_auth_user)
            .or(api_load_user)
            .or(api_create_contact)
            .or(api_delete_contact)
            .or(api_update_contact)
            .or(api_load_contacts)
            .recover(handlers::handle_rejection)
    )
        .run(([127, 0, 0, 1], 3000))
        .await
}

mod filters {
    use mongodb::Database;
    use warp::Filter;

    use crate::models::{AuthUserRequest, InsertContactRequest, RegisterUserRequest};

    pub fn with_register_user() -> impl Filter<Extract=(RegisterUserRequest, ), Error=warp::Rejection> + Clone {
        // When accepting a body, we want a JSON body
        // (and to reject huge payloads)...
        warp::body::content_length_limit(1024 * 16).and(warp::body::json())
    }

    pub fn with_auth_user() -> impl Filter<Extract=(AuthUserRequest, ), Error=warp::Rejection> + Clone {
        warp::body::content_length_limit(1024 * 16).and(warp::body::json())
    }

    pub fn with_contact() -> impl Filter<Extract=(InsertContactRequest, ), Error=warp::Rejection> + Clone {
        warp::body::content_length_limit(1024 * 16).and(warp::body::json())
    }

    // pub fn with_contact_length_limit<T: Send + Sync + DeserializeOwned>() -> impl Filter<Extract=(T, ), Error=warp::Rejection> + Clone {
    //     warp::body::content_length_limit(1024 * 16).and(warp::body::json())
    // }

    pub fn with_db(db: Database) -> impl Filter<Extract=(Database, ), Error=std::convert::Infallible> + Clone {
        warp::any().map(move || db.clone())
    }
}

mod handlers {
    use std::convert::Infallible;

    use bcrypt::{hash, verify};
    use jsonwebtoken::{decode, DecodingKey, encode, EncodingKey, Header, TokenData, Validation};
    use mongodb::{bson::{Bson, doc, Document, from_bson, oid, to_bson}, Database};
    use serde::{Deserialize, Serialize};
    use tokio::stream::StreamExt;
    use warp::{http::StatusCode, reject, Rejection};

    use crate::models::{AuthUserRequest, ContactResponse, DBContact, DeleteOptions, InsertContactRequest, LoadUserResponse, RegisterUserRequest, UpdateOptions};

    #[derive(Debug)]
    enum ApiErrors {
        DBError(String),
        ServerError(String),
        Custom(StatusCode, String),
    }

    impl reject::Reject for ApiErrors {}

    #[derive(Serialize)]
    struct ErrorResponse {
        code: u16,
        message: String,
    }

    impl From<&ApiErrors> for ErrorResponse {
        fn from(api_error: &ApiErrors) -> Self {
            match api_error {
                ApiErrors::DBError(msg) => {
                    ErrorResponse {
                        code: StatusCode::BAD_GATEWAY.as_u16(),
                        message: msg.to_owned(),
                    }
                }
                ApiErrors::ServerError(msg) => {
                    ErrorResponse {
                        code: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                        message: msg.to_owned(),
                    }
                }
                ApiErrors::Custom(code, msg) => {
                    ErrorResponse {
                        code: code.as_u16(),
                        message: msg.to_owned(),
                    }
                }
            }
        }
    }

    pub async fn handle_rejection(err: Rejection) -> Result<impl warp::Reply, Infallible> {
        if let Some(api_errors) = err.find::<ApiErrors>() {
            let error_response: ErrorResponse = api_errors.into();
            let json = warp::reply::json(&error_response);
            Ok(warp::reply::with_status(
                json,
                StatusCode::from_u16(error_response.code).unwrap_or(StatusCode::BAD_REQUEST),
            ))
        } else {
            Ok(warp::reply::with_status(
                warp::reply::json(&"Bad Request"),
                StatusCode::BAD_REQUEST,
            ))
        }
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct UserClaims {
        user_id: String
        // todo: add exp field and validate()
    }

    pub async fn auth_user(authorize_user: AuthUserRequest, db: Database) -> Result<impl warp::Reply, Rejection> {
        let user_doc: Document = db
            .collection("users")
            .find_one(doc! {"email": &authorize_user.email}, None)
            .await
            .map_err(|_err| reject::custom(ApiErrors::Custom(StatusCode::BAD_GATEWAY, "Db error".to_string())))?
            .ok_or_else(|| reject::custom(ApiErrors::Custom(StatusCode::BAD_REQUEST, "User not found".to_string())))?;

        let db_user_password = user_doc
            .get("password")
            .ok_or_else(|| reject::custom(ApiErrors::Custom(StatusCode::INTERNAL_SERVER_ERROR, "User password not found".to_string())))?
            .as_str()
            .ok_or_else(|| reject::custom(ApiErrors::Custom(StatusCode::INTERNAL_SERVER_ERROR, "Could not convert bson to string".to_string())))?;

        let does_password_match = verify(&authorize_user.password, db_user_password)
            .map_err(|_err| reject::custom(ApiErrors::Custom(StatusCode::INTERNAL_SERVER_ERROR, "Verification process failed".to_string())))?;

        if !does_password_match {
            return Err(reject::custom(ApiErrors::Custom(StatusCode::INTERNAL_SERVER_ERROR, "Incorrect password ".to_string())));
        }

        let user_id = user_doc
            .get_object_id("_id")
            .map_err(|_err| reject::custom(ApiErrors::Custom(StatusCode::INTERNAL_SERVER_ERROR, "User id not found".to_string())))?
            .to_string();

        Ok(warp::reply::json(&encode_to_token(user_id)?))
    }

    pub async fn load_user(token: String, db: Database) -> Result<impl warp::Reply, Rejection> {
        let token_data = decode_token(token)?;
        let user_object_id = oid::ObjectId::with_string(&token_data.claims.user_id)
            .map_err(|_err| reject::custom(ApiErrors::Custom(StatusCode::INTERNAL_SERVER_ERROR, "Failed to create an object id".to_string())))?;

        let user_doc = db
            .collection("users")
            .find_one(doc! {"_id": user_object_id}, None)
            .await
            .map_err(|_err| reject::custom(ApiErrors::Custom(StatusCode::BAD_GATEWAY, "Db error".to_string())))?
            .ok_or_else(|| reject::custom(ApiErrors::Custom(StatusCode::BAD_GATEWAY, "No user with id {} found".to_string())))? as Document;

        Ok(warp::reply::json(
            &LoadUserResponse::from(user_doc)
                .map_err(|_err| reject::custom(ApiErrors::Custom(StatusCode::INTERNAL_SERVER_ERROR, "Could not convert document user".to_string())))?
        ))
    }

    pub async fn register_user(register_user_request: RegisterUserRequest, db: Database) -> Result<impl warp::Reply, Rejection> {
        let hashed_password = hash(&register_user_request.password.to_owned(), 4)
            // todo: consider - error during hashing the password
            .map_err(|_err| reject::custom(ApiErrors::ServerError(StatusCode::INTERNAL_SERVER_ERROR.to_string())))?;

        let user_to_insert = RegisterUserRequest {
            password: hashed_password,
            ..register_user_request
        };

        let users = db.collection("users");
        let is_unique_email = users
            .find_one(doc! { "email": &user_to_insert.email }, None)
            .await
            .map_err(|_err| reject::custom(ApiErrors::DBError(_err.to_string())))?
            .is_none();

        if !is_unique_email {
            return Err(reject::custom(ApiErrors::Custom(StatusCode::BAD_REQUEST, "User already exists".to_owned())));
        }

        let doc_user = to_bson(&user_to_insert)
            // todo: consider - could not encode `user` into a bson value
            .map_err(|_err| reject::custom(ApiErrors::ServerError(StatusCode::INTERNAL_SERVER_ERROR.to_string())))?
            .as_document()
            // todo: consider - could not convert bson `contact` to document
            .ok_or_else(|| reject::custom(ApiErrors::ServerError(StatusCode::INTERNAL_SERVER_ERROR.to_string())))?
            .to_owned();

        let user_id = (users
            .insert_one(doc_user, None)
            .await
            .map_err(|_err| reject::custom(ApiErrors::DBError(StatusCode::BAD_GATEWAY.to_string())))?
            .inserted_id as Bson)
            .as_object_id()
            // todo: consider - could not get object_id
            .ok_or_else(|| reject::custom(ApiErrors::ServerError(StatusCode::INTERNAL_SERVER_ERROR.to_string())))?
            .to_string();

        Ok(warp::reply::with_status(encode_to_token(user_id)?, StatusCode::OK))
    }

    // todo: return whole object as response ?
    pub async fn create_contact(token: String, create_contact: InsertContactRequest, db: Database) -> Result<impl warp::Reply, Rejection> {
        let token_data = decode_token(token)?;

        let mut doc_contact = to_bson(&create_contact)
            // todo: consider - could not encode `contact` into a bson value
            .map_err(|_err| reject::custom(ApiErrors::ServerError(StatusCode::INTERNAL_SERVER_ERROR.to_string())))?
            .as_document_mut()
            // todo: consider - could not convert bson `contact` to document
            .ok_or_else(|| reject::custom(ApiErrors::ServerError(StatusCode::INTERNAL_SERVER_ERROR.to_string())))?
            .to_owned();


        doc_contact.insert("user_id", &token_data.claims.user_id);

        let inserted_contact = (db.collection("contacts")
            .insert_one(doc_contact.to_owned(), None)
            .await
            .map_err(|_err| reject::custom(ApiErrors::DBError(StatusCode::BAD_GATEWAY.to_string())))?
            .inserted_id as Bson).as_object_id()
            // todo: consider - could not get object_id
            .ok_or_else(|| reject::custom(ApiErrors::ServerError(StatusCode::INTERNAL_SERVER_ERROR.to_string())))?
            .to_string();

        Ok(warp::reply::with_status(inserted_contact, StatusCode::OK))
    }

    pub async fn delete_contact(token: String, opts: DeleteOptions, db: Database) -> Result<impl warp::Reply, Rejection> {
        let token_data = decode_token(token)?;
        let contacts = db.collection("contacts");

        let contact_object_id = oid::ObjectId::with_string(&opts.id)
            .map_err(|_err| reject::custom(ApiErrors::ServerError(StatusCode::INTERNAL_SERVER_ERROR.to_string())))?;

        let contact_user_id = (contacts.find_one(doc! {"_id" : &contact_object_id }, None)
            .await
            .map_err(|_err| reject::custom(ApiErrors::DBError(StatusCode::BAD_GATEWAY.to_string())))? as Option<Document>)
            // todo: consider - no contact with this {id} found
            .ok_or_else(|| reject::custom(ApiErrors::ServerError(StatusCode::INTERNAL_SERVER_ERROR.to_string())))?
            .get("user_id")
            // todo: consider - user_id key not found
            .ok_or_else(|| reject::custom(ApiErrors::ServerError(StatusCode::INTERNAL_SERVER_ERROR.to_string())))?
            .as_str()
            // todo: consider - could not convert user_id to string
            .ok_or_else(|| reject::custom(ApiErrors::ServerError(StatusCode::INTERNAL_SERVER_ERROR.to_string())))?
            .to_owned();

        if contact_user_id != token_data.claims.user_id {
            return Ok(StatusCode::UNAUTHORIZED);
        }

        contacts.delete_one(doc! {"_id" : &contact_object_id}, None)
            .await
            .map_err(|_err| reject::custom(ApiErrors::DBError(StatusCode::BAD_GATEWAY.to_string())))?;

        Ok(StatusCode::OK)
    }

    pub async fn update_contact(token: String, opts: UpdateOptions, insert_contact: InsertContactRequest, db: Database) -> Result<impl warp::Reply, Rejection> {
        let token_data = decode_token(token)?;

        let contacts = db.collection("contacts");
        let contact_object_id = oid::ObjectId::with_string(&opts.id)
            .map_err(|_err| reject::custom(ApiErrors::DBError(StatusCode::BAD_GATEWAY.to_string())))?;

        let contact_user_id = (contacts
            .find_one(doc! {"_id": &contact_object_id}, None)
            .await
            .map_err(|_err| reject::custom(ApiErrors::DBError(StatusCode::BAD_GATEWAY.to_string())))?
            .ok_or_else(|| reject::custom(ApiErrors::Custom(StatusCode::BAD_GATEWAY, "No contact found".to_owned())))?
            .get("user_id")
            // todo: consider - contact does not have user_id
            .ok_or_else(|| reject::custom(ApiErrors::Custom(StatusCode::UNAUTHORIZED, "contact does not have user_id".to_owned())))? as &Bson)
            .as_str()
            // todo: consider - could not convert to str
            .ok_or_else(|| reject::custom(ApiErrors::ServerError(StatusCode::INTERNAL_SERVER_ERROR.to_string())))?
            .to_string();

        if contact_user_id != token_data.claims.user_id {
            return Ok(StatusCode::UNAUTHORIZED);
        }
        let update = to_bson(&insert_contact)
            // todo: consider - could not convert to bson
            .map_err(|_err| reject::custom(ApiErrors::ServerError(StatusCode::INTERNAL_SERVER_ERROR.to_string())))?
            .as_document()
            // todo: consider - could not convert to document
            .ok_or_else(|| reject::custom(ApiErrors::ServerError(StatusCode::INTERNAL_SERVER_ERROR.to_string())))?
            .to_owned();

        contacts.find_one_and_update(
            doc! {"_id": &contact_object_id},
            doc! {"$set": update},
            None,
        )
            .await
            .map_err(|_err| reject::custom(ApiErrors::DBError(StatusCode::BAD_GATEWAY.to_string())))?;


        Ok(StatusCode::NO_CONTENT)
    }

    pub async fn load_contacts(token: String, db: Database) -> Result<impl warp::Reply, Rejection> {
        let token_data = decode_token(token)?;
        let cursor = db
            .collection("contacts")
            .find(doc! {"user_id" : &token_data.claims.user_id}, None)
            .await
            .map_err(|_err| reject::custom(ApiErrors::DBError(StatusCode::BAD_GATEWAY.to_string())))?;

        let results = cursor
            .map(|item| Ok(from_bson(Bson::Document(item?))?))
            .collect::<Result<Vec<DBContact>, mongodb::error::Error>>()
            .await
            .map_err(|_err| reject::custom(ApiErrors::DBError(StatusCode::BAD_GATEWAY.to_string())))?
            .into_iter()
            .map(|v| v.into())
            .collect::<Vec<ContactResponse>>();

        Ok(warp::reply::json(&results))
    }

    fn decode_token(token: String) -> Result<TokenData<UserClaims>, Rejection> {
        decode::<UserClaims>(
            &token,
            &DecodingKey::from_secret("secret".as_ref()),
            &Validation { validate_exp: false, ..Default::default() },
        ).map_err(|err| reject::custom(ApiErrors::Custom(StatusCode::INTERNAL_SERVER_ERROR, err.to_string())))
    }

    fn encode_to_token(user_id: String) -> Result<String, Rejection> {
        encode(
            &Header::default(),
            &UserClaims { user_id },
            &EncodingKey::from_secret("secret".as_ref()),
        ).map_err(|err| reject::custom(ApiErrors::Custom(StatusCode::INTERNAL_SERVER_ERROR, err.to_string())))
    }
}

mod models {
    use mongodb::bson::{Document, oid};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize)]
    pub struct DBUser {
        #[serde(rename = "_id")]
        pub id: oid::ObjectId,
        pub name: String,
        pub email: String,
        pub password: String,
        // date: todo: address time-date
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct DBContact {
        #[serde(rename = "_id")]
        pub id: oid::ObjectId,
        pub name: String,
        pub email: String,
        pub phone: Option<String>,
        #[serde(rename = "type")]
        pub _type: Option<String>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct ContactResponse {
        pub id: String,
        pub name: String,
        pub email: String,
        pub phone: Option<String>,
        #[serde(rename = "type")]
        pub _type: Option<String>,
    }

    impl From<DBContact> for ContactResponse {
        fn from(db_contact: DBContact) -> Self {
            ContactResponse {
                id: db_contact.id.to_string(),
                name: db_contact.name,
                email: db_contact.email,
                phone: db_contact.phone,
                _type: db_contact._type,
            }
        }
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct DeleteOptions {
        pub id: String,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct UpdateOptions {
        pub id: String
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct RegisterUserRequest {
        pub name: String,
        pub email: String,
        pub password: String,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct LoadUserResponse {
        pub id: String,
        pub name: String,
        pub email: String,
    }

    impl From<DBUser> for LoadUserResponse {
        fn from(db_user: DBUser) -> Self {
            LoadUserResponse {
                id: db_user.id.to_string(),
                name: db_user.name,
                email: db_user.email,
            }
        }
    }

    // todo: implement From<Document>
    impl LoadUserResponse {
        pub fn from(doc: Document) -> Result<Self, String> {
            match (doc.get_object_id("_id"), doc.get_str("name"), doc.get_str("email")) {
                (Ok(id), Ok(name), Ok(email)) => {
                    Ok(
                        LoadUserResponse {
                            id: id.to_string(),
                            name: name.to_string(),
                            email: email.to_string(),
                        }
                    )
                }
                (_, _, _) => {
                    Err("Error converting document to LoadedUser response".to_owned())
                }
            }
        }
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct AuthUserRequest {
        pub email: String,
        pub password: String,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct InsertContactRequest {
        name: String,
        email: String,
        phone: Option<String>,
        #[serde(rename = "type")]
        _type: Option<String>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct UpdateContactRequest {
        name: String,
        email: String,
        phone: Option<String>,
        #[serde(rename = "type")]
        _type: Option<String>,
    }
}

mod db {
    use mongodb::{Client, Database};

    pub async fn connect() -> Database {
        // let mut client_options = ClientOptions::parse(mongo_uri).await.unwrap();
        // let client = Client::with_options(client_options).unwrap();
        let mongo_uri = "mongodb+srv://adrian123:adrian123@ckcluster-s8sds.mongodb.net/contact_keeper_db?retryWrites=true&w=majority";
        let client = Client::with_uri_str(mongo_uri).await.unwrap();
        let db_name = "contact_keeper_db";

        client.database(db_name)
    }
}

// TODO's
// - update README.md
// - revise errors sent to client
// - improve how errors are constructed
// - add date to `user` struct
// - use with_contact_length_limit instead of with_register_user, with_auth_user, with_contact
// - implement From<Document> for LoadUserResponse
// - extract "secret" and "mongo_uri" to const
// - add exp field to UserClaims, and use proper validation error

// - define a separate interface for communicating with DB (aka polymorphism, dependency inversion principle)

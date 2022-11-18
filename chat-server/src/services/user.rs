use std::convert::Infallible;

use crate::{User, Users};
use chat_core::requests::{Register, RegisterResponse};
use serde::Serialize;
use uuid::Uuid;
use warp::{hyper::StatusCode, Reply};

use super::ResponseError;

/// Endpoint to register a user.
/// Takes a `Register` in its request body with the necessary information
/// about the client to register.
pub async fn register_user(register: Register, users: Users) -> Result<impl warp::Reply, Infallible> {
    let id = Uuid::new_v4();
    let user = User::new(id, register.username().clone(), register.key_info().clone());
    users.write().await.insert(id, user);

    println!(
        "User '{username}' registered with id: '{id}'",
        username = register.username()
    );

    Ok(warp::reply::with_status(
        serde_json::to_string(&RegisterResponse::new(id))
            .expect("serialization in register failed"),
        StatusCode::OK,
    ))
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Profile {
    id: Uuid,
    username: String,
}

impl Reply for Profile {
    fn into_response(self) -> warp::reply::Response {
        warp::reply::json(&self).into_response()
    }
}

/// Get a user's profile by its user id.
pub async fn get_user_profile_by_id(users: Users, id: Uuid) -> Result<Profile, ResponseError> {
    if let Some(user) = users.read().await.get(&id) {
        Ok(Profile {
            id: id.clone(),
            username: user.username.clone(),
        })
    } else {
        Err(ResponseError::UserNotFound(id.to_owned()))
    }
}

#[cfg(test)]
mod test {
    use chat_core::x3dh::PublishingKey;
    use fake::{Fake, Faker};

    use crate::User;

    use super::*;

    #[tokio::test]
    async fn simple() {
        let id = Uuid::new_v4();
        let username: String = Faker.fake::<String>();
        let user = User::new(id, username.clone(), PublishingKey::gen_fake());
        let users = Users::default();
        users.write().await.insert(id, user);

        // Act
        let actual = get_user_profile_by_id(users, id).await;
        assert!(actual.is_ok());
        assert_eq!(actual.unwrap(), Profile { id, username });
    }

    #[tokio::test]
    async fn user_not_found() {
        let id = Uuid::new_v4();
        let users = Users::default();

        // Act
        let actual = get_user_profile_by_id(users, id).await;
        assert_eq!(actual.err().unwrap(), ResponseError::UserNotFound(id));
    }
}

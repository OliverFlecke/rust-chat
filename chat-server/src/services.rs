pub mod user;

use std::convert::Infallible;

use chat_core::{requests::PreKeyBundleRequest, x3dh::PreKeyBundle};
use uuid::Uuid;
use warp::{hyper::StatusCode, reject::Reject, reply, Rejection, Reply};

use crate::Users;

#[derive(Debug, PartialEq)]
pub enum ResponseError {
    UserNotFound(Uuid),
}

impl Reject for ResponseError {}

impl From<Rejection> for ResponseError {
    fn from(_: Rejection) -> Self {
        todo!()
    }
}

/// Handle errors in the pipeline.
pub async fn response_error_handler(err: Rejection) -> Result<impl Reply, Infallible> {
    if err.is_not_found() {
        Ok(reply::with_status("NOT_FOUND", StatusCode::NOT_FOUND))
    } else if let Some(e) = err.find::<ResponseError>() {
        match e {
            ResponseError::UserNotFound(_id) => {
                // TODO: The user id should be included in this response
                Ok(reply::with_status(
                    "User not found",
                    StatusCode::BAD_REQUEST,
                ))
            }
        }
    } else {
        eprintln!("unhandled rejection: {:?}", err);
        Ok(reply::with_status("", StatusCode::INTERNAL_SERVER_ERROR))
    }
}

/// Get a `PreKeyBundle` for a given user.
///
/// Returns a `UserNotFound` error if the requested user has not registered
/// on the server.
pub async fn get_pre_key_bundle_for_user(
    request: PreKeyBundleRequest,
    users: Users,
) -> Result<PreKeyBundle, ResponseError> {
    match users.write().await.get_mut(request.user_id()) {
        Some(user) => Ok(PreKeyBundle::create_from(user.key_info_mut())),
        None => Err(ResponseError::UserNotFound(request.user_id().to_owned())),
    }
}

#[cfg(test)]
mod test {
    use chat_core::x3dh::{KeyStore, PreKeyBundle, PublishingKey};
    use fake::{Fake, Faker};
    use uuid::Uuid;

    use crate::User;

    use super::*;

    #[tokio::test]
    async fn get_pre_key_bundle_for_user_not_found() {
        // Attempt to get a user, which does not exist, should result in an error
        let id = Uuid::new_v4();
        let request = PreKeyBundleRequest::new(id.clone());

        // Act
        let result = get_pre_key_bundle_for_user(request, Users::default())
            .await
            .err();

        assert_eq!(result, Some(ResponseError::UserNotFound(id)));
    }

    #[tokio::test]
    async fn get_pre_key_bundle_for_user_success() {
        let id = Uuid::new_v4();
        let request = PreKeyBundleRequest::new(id.clone());
        let username = Faker.fake::<String>();
        let mut key_info = PublishingKey::from(KeyStore::gen());

        let users = Users::default();
        users
            .write()
            .await
            .insert(id, User::new(id, username, key_info.clone()));

        // Act
        let result = get_pre_key_bundle_for_user(request, users.clone())
            .await
            .unwrap();

        assert_eq!(result, PreKeyBundle::create_from(&mut key_info));
        assert_eq!(
            99,
            users
                .read()
                .await
                .get(&id)
                .unwrap()
                .key_info()
                .one_time_pre_keys_len()
        );
    }
}

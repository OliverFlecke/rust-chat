use chat_core::requests::ProfileResponse;
use uuid::Uuid;

use crate::Server;

impl Server {
    pub async fn get_user_profile_by_id(&self, id: &Uuid) -> Result<ProfileResponse, ()> {
        match reqwest::get(format!("http://{}/user/{}", self.host, id)).await {
            Ok(x) => Ok(serde_json::from_str(&x.text().await.unwrap()).unwrap()), // TODO: Error handling
            Err(_) => Err(()),
        }
    }

    pub async fn get_users(&self) -> Result<Vec<ProfileResponse>, ()> {
        todo!()
    }
}

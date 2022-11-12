use std::{error::Error, fs};

use crate::User;

/// Read the user's data from disk.
pub async fn read_user_data(file: String) -> Result<User, Box<dyn Error>> {
    let user_data = fs::read(file)?;
    Ok(serde_json::from_slice::<User>(&user_data)?)
}

/// Persist the current user data to file.
pub async fn write_user(filename: &str, user: &User) -> Result<(), Box<dyn Error>> {
    let data = serde_json::to_string(&user).expect("user to be serialized");
    fs::write(filename, data)?;

    Ok(())
}

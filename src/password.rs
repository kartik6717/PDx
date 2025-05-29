pub struct Passwords {
    pub user_password: Option<String>,
    pub owner_password: Option<String>,
}

impl Passwords {
    pub fn new() -> Self {
        Self {
            user_password: None,
            owner_password: None,
        }
    }

    pub fn with_user_password(password: String) -> Self {
        Self {
            user_password: Some(password),
            owner_password: None,
        }
    }

    pub fn with_owner_password(password: String) -> Self {
        Self {
            user_password: None,
            owner_password: Some(password),
        }
    }

    pub fn both(user: String, owner: String) -> Self {
        Self {
            user_password: Some(user),
            owner_password: Some(owner),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.user_password.is_none() && self.owner_password.is_none()
    }
}
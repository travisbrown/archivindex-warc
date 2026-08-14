#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Passed,
    Failed,
    Error,
    Unavailable,
}

impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Error => "error",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Debug)]
pub struct ValidationResult {
    pub validator: &'static str,
    pub status: Status,
    pub summary: String,
    pub details: String,
}

impl ValidationResult {
    pub fn passed(validator: &'static str, summary: impl Into<String>, details: String) -> Self {
        Self {
            validator,
            status: Status::Passed,
            summary: summary.into(),
            details,
        }
    }

    pub fn failed(validator: &'static str, summary: impl Into<String>, details: String) -> Self {
        Self {
            validator,
            status: Status::Failed,
            summary: summary.into(),
            details,
        }
    }

    pub fn error(validator: &'static str, error: impl std::fmt::Display) -> Self {
        Self::error_with_details(validator, error, String::new())
    }

    pub fn error_with_details(
        validator: &'static str,
        error: impl std::fmt::Display,
        details: String,
    ) -> Self {
        Self {
            validator,
            status: Status::Error,
            summary: error.to_string(),
            details,
        }
    }

    pub fn unavailable(validator: &'static str, error: impl std::fmt::Display) -> Self {
        Self {
            validator,
            status: Status::Unavailable,
            summary: error.to_string(),
            details: String::new(),
        }
    }

    pub fn is_success(&self) -> bool {
        self.status == Status::Passed
    }
}

#[macro_use]
extern crate error_chain;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate which;

use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

error_chain! {
    foreign_links {
        JsonParse(::serde_json::error::Error) #[doc = "Failed to parse JSON"];
        Io(::std::io::Error)
            #[doc = "IO error while calling `op` command"];
        SessionVar(::std::env::VarError)
            #[doc = "OP session environment variable was not valid UTF-8"];
        StdErrUtf8(::std::string::FromUtf8Error)
            #[doc = "Std error output from op was not valid UTF-8"];
    }
    errors {
        #[doc = "op command not found in path."]
        MissingOpCommand {
            description("op command not found in path")
        }
        #[doc = "Could not find any session environment variable."]
        MissingSessionVariable {
            description("could not find any session environment variable")
        }
        #[doc = "More than one session environment variable found."]
        MultipleSessionVariables(domains: Vec<String>) {
            description("more than one session environment variable found")
            display("more than one session environment variable found: {:?}", domains)
        }
        #[doc = "`op get` error"]
        GetCommand(uuid: String, stderr: String, status: ExitStatus) {
            description("op get error")
            display("op get error for {} code: {}, {}", uuid, status, stderr)
        }
        #[doc = "`op --version` error"]
        VersionCommand(stderr: String, status: ExitStatus) {
            description("op --version error")
            display("op --version error code: {}, {}", status, stderr)
        }
    }
}

///
///
#[derive(Debug, Clone)]
pub struct Op {
    command: PathBuf,
}

impl Op {
    /// # Example
    ///
    /// ```
    /// # extern crate _1password;
    /// use _1password::Op;
    ///
    /// let op = Op::new("op");
    /// println!("Op Version: {}", op.version().unwrap());
    /// ```
    pub fn new<P: AsRef<Path>>(command: P) -> Op {
        Op {
            command: command.as_ref().to_owned(),
        }
    }

    /// Find `op` command line utility by search the current PATH environment variable.
    ///
    /// # Example
    ///
    /// ```
    /// # extern crate _1password;
    /// use _1password::Op;
    ///
    /// let op = Op::which().unwrap();
    /// println!("Op Version: {}", op.version().unwrap());
    /// ```
    pub fn which() -> Result<Op> {
        if let Ok(p) = which::which("op") {
            Ok(Op {
                command: p,
            })
        } else {
            Err(ErrorKind::MissingOpCommand.into())
        }
    }

    /// Path to `op` command
    pub fn command(&self) -> &Path {
        &self.command
    }

    /// Returns version of `op` that this struct uses.
    pub fn version(&self) -> Result<String> {
        let output = Command::new(&self.command)
                .arg("--version")
                .output()?;
        let stdout = String::from_utf8(output.stdout)?;
        let stderr = String::from_utf8(output.stderr)?;
        if let Some(1) = output.status.code() {
            Ok(stdout.trim().to_owned())
        } else {
            Err(ErrorKind::VersionCommand(stderr, output.status).into())
        }
    }

    /*
    pub fn signin_subdomain(&self, subdomain: &str, password: &str) -> OpSession {

    }

    pub fn signin(&self, signinaddress: &str, emailaddress: &str, secretkey: &str, password: &str) -> OpSession {

    }
    */

    /// Make new session with the specified session token.
    pub fn session(&self, session: &str) -> OpSession {
        OpSession {
            config: self.clone(),
            session: session.to_owned(),
        }
    }

    /// Lookup session token for the supplied subdomain in environment.
    /// This will look for an environment variable named `OP_SESSION_<subdomain>` and if found
    /// will return a new session that uses the session token stored in that environment variable.
    pub fn env_account_session(&self, subdomain: &str) -> Result<OpSession> {
        match env::var(format!("OP_SESSION_{}", subdomain)) {
            Err(env::VarError::NotPresent) => Err(ErrorKind::MissingSessionVariable.into()),
            Err(err) => Err(err.into()),
            Ok(session) => Ok(OpSession {
                config: self.clone(),
                session: session,
            })
        }
    }

    /// Lookup session token in environment.
    /// This will look for any environment variables matching the pattern `OP_SESSION_*` and if
    /// found will return a new session that uses the session token stored in that environment
    /// variable.
    ///
    /// If more than one environment variable matching the pattern is found and error is returned.
    pub fn env_session(&self) -> Result<OpSession> {
        let vars : Vec<(String,String)> = env::vars().filter(|(key, _)| key.starts_with("OP_SESSION_") ).collect();
        match vars.len() {
            0 => Err(ErrorKind::MissingSessionVariable.into()),
            1 => {
                Ok(OpSession {
                    config: self.clone(),
                    session: vars.into_iter().next().unwrap().1,
                })
            },
            _ => {
                let names : Vec<String> = vars.into_iter().map(|(key, _)| key).collect();
                Err(ErrorKind::MultipleSessionVariables(names).into())
            }
        }
    }
}

/// A configured session what can be used to actually lookup information in 1Password.
#[derive(Debug, Clone)]
pub struct OpSession {
    config: Op,
    session: String,
}

impl OpSession {
    /// Get item with specified UUID.
    ///
    /// This calls `op get item` and parses the returned JSON.
    pub fn get_item(&self, uuid: &str) -> Result<OpItem> {
        let output = Command::new(&self.config.command)
                .args(&["get", "item", "--session"])
                .arg(&self.session)
                .arg(&uuid)
                .output()?;
        if output.status.success() {
            Ok(serde_json::from_slice(&output.stdout)?)
        } else {
            let stderr = String::from_utf8(output.stderr)?;
            Err(ErrorKind::GetCommand(uuid.to_owned(), stderr, output.status).into())
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OpItemOverview {
    pub ainfo: String,
    pub title: String
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OpItemField {
    pub designation: Option<String>,
    pub name: String,
    #[serde(rename="type")]
    pub field_type: String,
    pub value: String
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum OpItemDetails {
    Password { password: String },
    Login { fields: Vec<OpItemField> },
}

/// Item returned from `OpSession::get_item`
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct OpItem {
    pub uuid: String,
    pub vault_uuid: String,
    pub changer_uuid: String,
    pub overview: OpItemOverview,
    pub details: OpItemDetails,
}

impl OpItem {
    /// Return password of this item if any.
    pub fn password(&self) -> Option<String> {
        match &self.details {
            &OpItemDetails::Password{ ref password } => Some(password.clone()),
            &OpItemDetails::Login{ ref fields } => {
                let p : Option<String> = Some("password".to_string());
                fields.iter()
                    .find(|ref x| x.designation == p)
                    .map(|x| x.value.clone())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

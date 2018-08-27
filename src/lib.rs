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
        Json(::serde_json::error::Error);
        Fmt(::std::fmt::Error);
        Io(::std::io::Error);
        SessionVarError(::std::env::VarError);
        StdErrUtf8(::std::string::FromUtf8Error);
    }
    errors {
        MissingOpCommand {
            description("op command not found in path")
        }
        MissingSessionVariable {
            description("could not find any session environment variable")
        }
        MultipleSessionVariables(domains: Vec<String>) {
            description("more than one session environment variable found")
            display("more than one session environment variable found: {:?}", domains)
        }
        GetError(uuid: String, stderr: String, status: ExitStatus) {
            description("op get error")
            display("op get error for {} code: {}, {}", uuid, status, stderr)
        }
    }
}

#[derive(Debug, Clone)]
pub struct Op {
    command: PathBuf,
}

impl Op {
    pub fn new<P: AsRef<Path>>(command: P) -> Op {
        Op {
            command: command.as_ref().to_owned(),
        }
    }

    pub fn which() -> Result<Op> {
        if let Ok(p) = which::which("op") {
            Ok(Op {
                command: p,
            })
        } else {
            Err(ErrorKind::MissingOpCommand.into())
        }
    }

    pub fn command(&self) -> &Path {
        &self.command
    }

    /*
    pub fn signin_subdomain(&self, subdomain: &str) -> OpSession {

    }

    pub fn signin(&self, signinaddress: &str, emailaddress: &str, secretkey: &str) -> OpSession {

    }
    */

    pub fn session(&self, session: &str) -> OpSession {
        OpSession {
            config: self.clone(),
            session: session.to_owned(),
        }
    }

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

#[derive(Debug, Clone)]
pub struct OpSession {
    config: Op,
    session: String,
}

impl OpSession {
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
            Err(ErrorKind::GetError(uuid.to_owned(), stderr, output.status).into())
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OpItemOverview {
    ainfo: String,
    title: String
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OpItemField {
    designation: Option<String>,
    name: String,
    #[serde(rename="type")]
    field_type: String,
    value: String
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum OpItemDetails {
    Password { password: String },
    Login { fields: Vec<OpItemField> },
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct OpItem {
    uuid: String,
    vault_uuid: String,
    changer_uuid: String,
    overview: OpItemOverview,
    details: OpItemDetails,
}

impl OpItem {
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

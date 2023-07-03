use std::{convert::Infallible, path::PathBuf};

use crate::{CreatePoolError, Manager, Pool, PoolBuilder, PoolConfig, Runtime};

#[derive(Clone, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde_1::Deserialize, serde_1::Serialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_1"))]
pub struct Config {
    pub path: PathBuf,
    pub pool: Option<PoolConfig>,
}

impl Config {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            pool: None,
        }
    }

    pub fn create_pool(&self, runtime: Runtime) -> Result<Pool, CreatePoolError> {
        self.builder(runtime)
            .map_err(CreatePoolError::Config)?
            .runtime(runtime)
            .build()
            .map_err(CreatePoolError::Build)
    }

    pub fn builder(&self, runtime: Runtime) -> Result<PoolBuilder, ConfigError> {
        let manager = Manager::from_config(self, runtime);
        Ok(Pool::builder(manager)
            .config(self.get_pool_config())
            .runtime(runtime))
    }

    #[must_use]
    pub fn get_pool_config(&self) -> PoolConfig {
        self.pool.unwrap_or_default()
    }
}

pub type ConfigError = Infallible;

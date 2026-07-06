// Copyright (c) 2023 Huawei Device Co., Ltd.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::error::Error;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use ylong_http::request::uri::Uri;

use crate::error::{ErrorKind, HttpClientError};
use crate::sync_impl::Connector;
use crate::util::dispatcher::{Conn, ConnDispatcher, Dispatcher};
use crate::util::pool::{Pool, PoolKey};
use crate::util::progress::SpeedConfig;

pub(crate) struct ConnPool<C, S> {
    pool: Pool<PoolKey, Conns<S>>,
    connector: Arc<C>,
}

impl<C: Connector> ConnPool<C, C::Stream> {
    pub(crate) fn new(connector: C) -> Self {
        Self {
            pool: Pool::new(),
            connector: Arc::new(connector),
        }
    }

    pub(crate) fn connect_to(&self, uri: Uri) -> Result<Conn<C::Stream>, HttpClientError> {
        let key = PoolKey::new(
            uri.scheme().unwrap().clone(),
            uri.authority().unwrap().clone(),
        );

        self.pool
            .get(key, Conns::new, 1, SpeedConfig::none())
            .conn(|| self.connector.clone().connect(&uri))
    }
}

pub(crate) struct Conns<S> {
    list: Arc<Mutex<Vec<ConnDispatcher<S>>>>,
}

impl<S> Conns<S> {
    fn new(_allowed_num: usize, _speed_config: SpeedConfig) -> Self {
        Self {
            list: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl<S> Clone for Conns<S> {
    fn clone(&self) -> Self {
        Self {
            list: self.list.clone(),
        }
    }
}

impl<S: Read + Write + 'static> Conns<S> {
    fn conn<F, E>(&self, connect_fn: F) -> Result<Conn<S>, HttpClientError>
    where
        F: FnOnce() -> Result<S, E>,
        E: Into<Box<dyn Error + Send + Sync>>,
    {
        let mut list = self.list.lock().unwrap();
        let mut conn = None;
        let mut idx = 0;
        while idx < list.len() {
            // Discard invalid dispatchers.
            if list[idx].is_shutdown() {
                list.remove(idx);
                continue;
            }
            if conn.is_none() {
                conn = list[idx].dispatch();
            }
            idx += 1;
        }

        if let Some(conn) = conn {
            Ok(conn)
        } else {
            let dispatcher = ConnDispatcher::http1(
                connect_fn().map_err(|e| HttpClientError::from_error(ErrorKind::Connect, e))?,
            );
            // We must be able to get the `Conn` here.
            let conn = dispatcher.dispatch().unwrap();
            list.push(dispatcher);
            Ok(conn)
        }
    }

    #[cfg(all(test, feature = "http1_1"))]
    fn h1_list_capacity_for_test(&self) -> usize {
        self.list.lock().unwrap().capacity()
    }
}

#[cfg(all(test, feature = "http1_1"))]
mod tests {
    use std::io::Cursor;

    use crate::util::dispatcher::ConnDispatcher;
    use crate::util::progress::SpeedConfig;

    use super::Conns;

    #[test]
    fn ut_conn_preserves_list_capacity() {
        let conns = Conns::<Cursor<Vec<u8>>>::new(1, SpeedConfig::none());
        {
            let mut list = conns.list.lock().unwrap();
            list.push(ConnDispatcher::http1(Cursor::new(Vec::new())));
            list.reserve(64);
        }
        let capacity = conns.h1_list_capacity_for_test();
        assert!(capacity >= 64);

        for _ in 0..8 {
            let conn = conns
                .conn(|| -> Result<Cursor<Vec<u8>>, std::io::Error> {
                    panic!("expected reusable HTTP/1 connection")
                })
                .expect("connection reuse failed");
            drop(conn);
            assert_eq!(conns.h1_list_capacity_for_test(), capacity);
        }
    }
}

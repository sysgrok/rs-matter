/*
 *
 *    Copyright (c) 2020-2022 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

use core::future::Future;

use super::{AsyncHandler, Node};

pub trait DataModelHandler {
    type DataModelHandlerGuard<'a>: DataModelHandlerGuard
    where
        Self: 'a;

    async fn access(&self) -> Self::DataModelHandlerGuard<'_>;
}

impl<T> DataModelHandler for &T
where
    T: DataModelHandler,
{
    type DataModelHandlerGuard<'a>
        = T::DataModelHandlerGuard<'a>
    where
        Self: 'a;

    fn access(&self) -> impl Future<Output = Self::DataModelHandlerGuard<'_>> {
        (**self).access()
    }
}

impl<H: AsyncHandler> DataModelHandler for (Node<'_>, H) {
    type DataModelHandlerGuard<'g>
        = (Node<'g>, &'g H)
    where
        Self: 'g;

    async fn access(&self) -> Self::DataModelHandlerGuard<'_> {
        (
            Node {
                endpoints: self.0.endpoints,
            },
            &self.1,
        )
    }
}

pub trait DataModelHandlerGuard {
    fn node(&self) -> Node<'_>;

    fn handler(&self) -> impl AsyncHandler + '_;
}

impl<T> DataModelHandlerGuard for &T
where
    T: DataModelHandlerGuard,
{
    fn node(&self) -> Node<'_> {
        (**self).node()
    }

    fn handler(&self) -> impl AsyncHandler + '_ {
        (**self).handler()
    }
}

impl<H: AsyncHandler> DataModelHandlerGuard for (Node<'_>, H) {
    fn node(&self) -> Node<'_> {
        Node {
            endpoints: self.0.endpoints,
        }
    }

    fn handler(&self) -> impl AsyncHandler + '_ {
        &self.1
    }
}

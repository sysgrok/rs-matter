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

use crate::error::Error;
use crate::utils::rand::Rand;

#[allow(non_snake_case)]

pub struct CryptoSpake2 {}

impl CryptoSpake2 {
    #[allow(non_snake_case)]
    pub fn new() -> Result<Self, Error> {
        Ok(Self {})
    }

    // Computes w0 from w0s respectively
    pub fn set_w0_from_w0s(&mut self, w0s: &[u8]) -> Result<(), Error> {
        // From the Matter Spec,
        //         w0 = w0s mod p
        //   where p is the order of the curve

        Ok(())
    }

    pub fn set_w1_from_w1s(&mut self, w1s: &[u8]) -> Result<(), Error> {
        // From the Matter Spec,
        //         w1 = w1s mod p
        //   where p is the order of the curve

        Ok(())
    }

    pub fn set_w0(&mut self, w0: &[u8]) -> Result<(), Error> {
        Ok(())
    }

    pub fn set_w1(&mut self, w1: &[u8]) -> Result<(), Error> {
        Ok(())
    }

    #[allow(non_snake_case)]
    #[allow(dead_code)]
    pub fn set_L(&mut self, w1s: &[u8]) -> Result<(), Error> {
        // From the Matter spec,
        //        L = w1 * P
        //    where P is the generator of the underlying elliptic curve
        Ok(())
    }

    #[allow(non_snake_case)]
    #[allow(dead_code)]
    pub fn set_L_from_w1s(&mut self, w1s: &[u8]) -> Result<(), Error> {
        // From the Matter spec,
        //        L = w1 * P
        //    where P is the generator of the underlying elliptic curve
        Ok(())
    }

    #[allow(non_snake_case)]
    pub fn get_pB(&mut self, pB: &mut [u8], _rand: Rand) -> Result<(), Error> {
        // From the SPAKE2+ spec (https://datatracker.ietf.org/doc/draft-bar-cfrg-spake2plus/)
        //   for y
        //   - select random y between 0 to p
        //   - Y = y*P + w0*N
        //   - pB = Y

        Ok(())
    }

    #[allow(non_snake_case)]
    pub fn get_TT_as_verifier(
        &mut self,
        context: &[u8],
        pA: &[u8],
        pB: &[u8],
        out: &mut [u8],
    ) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use openssl::bn::BigNum;
    use openssl::ec::{EcPoint, PointConversionForm};

    use crate::sc::spake2p::test_vectors::test_vectors::*;

    use super::CryptoSpake2;

    #[test]
    #[allow(non_snake_case)]
    fn test_get_X() {
        for t in RFC_T {
            let mut c = CryptoSpake2::new().unwrap();
            let x = BigNum::from_slice(&t.x).unwrap();
            c.set_w0(&t.w0).unwrap();
            let P = c.group.generator();

            let r = CryptoSpake2::do_add_mul(P, &x, &c.M, &c.w0, &c.group, &mut c.bn_ctx).unwrap();
            assert_eq!(
                t.X,
                r.to_bytes(&c.group, PointConversionForm::UNCOMPRESSED, &mut c.bn_ctx)
                    .unwrap()
                    .as_slice()
            );
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_get_Y() {
        for t in RFC_T {
            let mut c = CryptoSpake2::new().unwrap();
            let y = BigNum::from_slice(&t.y).unwrap();
            c.set_w0(&t.w0).unwrap();
            let P = c.group.generator();
            let r = CryptoSpake2::do_add_mul(P, &y, &c.N, &c.w0, &c.group, &mut c.bn_ctx).unwrap();
            assert_eq!(
                t.Y,
                r.to_bytes(&c.group, PointConversionForm::UNCOMPRESSED, &mut c.bn_ctx)
                    .unwrap()
                    .as_slice()
            );
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_get_ZV_as_prover() {
        for t in RFC_T {
            let mut c = CryptoSpake2::new().unwrap();
            let x = BigNum::from_slice(&t.x).unwrap();
            c.set_w0(&t.w0).unwrap();
            c.set_w1(&t.w1).unwrap();
            let Y = EcPoint::from_bytes(&c.group, &t.Y, &mut c.bn_ctx).unwrap();
            let (Z, V) = CryptoSpake2::get_ZV_as_prover(
                &c.w0,
                &c.w1,
                &mut c.N,
                &Y,
                &x,
                &c.order,
                &c.group,
                &mut c.bn_ctx,
            )
            .unwrap();

            assert_eq!(
                t.Z,
                Z.to_bytes(&c.group, PointConversionForm::UNCOMPRESSED, &mut c.bn_ctx)
                    .unwrap()
                    .as_slice()
            );
            assert_eq!(
                t.V,
                V.to_bytes(&c.group, PointConversionForm::UNCOMPRESSED, &mut c.bn_ctx)
                    .unwrap()
                    .as_slice()
            );
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_get_ZV_as_verifier() {
        for t in RFC_T {
            let mut c = CryptoSpake2::new().unwrap();
            let y = BigNum::from_slice(&t.y).unwrap();
            c.set_w0(&t.w0).unwrap();
            let X = EcPoint::from_bytes(&c.group, &t.X, &mut c.bn_ctx).unwrap();
            let L = EcPoint::from_bytes(&c.group, &t.L, &mut c.bn_ctx).unwrap();
            let (Z, V) = CryptoSpake2::get_ZV_as_verifier(
                &c.w0,
                &L,
                &mut c.M,
                &X,
                &y,
                &c.order,
                &c.group,
                &mut c.bn_ctx,
            )
            .unwrap();

            assert_eq!(
                t.Z,
                Z.to_bytes(&c.group, PointConversionForm::UNCOMPRESSED, &mut c.bn_ctx)
                    .unwrap()
                    .as_slice()
            );
            assert_eq!(
                t.V,
                V.to_bytes(&c.group, PointConversionForm::UNCOMPRESSED, &mut c.bn_ctx)
                    .unwrap()
                    .as_slice()
            );
        }
    }
}

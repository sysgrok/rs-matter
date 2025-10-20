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

use core::fmt::Write;

use verhoeff::Verhoeff;

use crate::BasicCommData;

impl BasicCommData {
    /// Compute the manual pairing code string from the commissioning data
    pub fn compute_pairing_code(&self) -> heapless::String<11> {
        // 0: no Vendor ID and Product ID present in Manual Pairing Code
        const VID_PID_PRESENT: u8 = 0;

        let BasicCommData {
            password,
            discriminator,
            ..
        } = self;

        let mut digits = heapless::String::<10>::new();
        write_unwrap!(
            &mut digits,
            "{}{:0>5}{:0>4}",
            (VID_PID_PRESENT << 2) | (discriminator >> 10) as u8,
            ((discriminator & 0x300) << 6) | (*password & 0x3FFF) as u16,
            *password >> 14
        );

        let mut final_digits = heapless::String::<11>::new();
        write_unwrap!(
            &mut final_digits,
            "{}{}",
            digits,
            digits.calculate_verhoeff_check_digit()
        );

        final_digits
    }

    /// Compute the manual pairing code string from the commissioning data
    /// and return it in a pretty format with dashes.
    pub fn compute_pretty_pairing_code(&self) -> heapless::String<13> {
        let pairing_code = self.compute_pairing_code();

        let mut pretty = heapless::String::new();
        unwrap!(pretty.push_str(&pairing_code[..4]));
        unwrap!(pretty.push('-'));
        unwrap!(pretty.push_str(&pairing_code[4..8]));
        unwrap!(pretty.push('-'));
        unwrap!(pretty.push_str(&pairing_code[8..]));

        pretty
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_compute_pairing_code() {
        let comm_data = BasicCommData {
            password: 123456,
            discriminator: 250,
        };
        let pairing_code = comm_data.compute_pairing_code();
        assert_eq!(pairing_code, "00876800071");

        let comm_data = BasicCommData {
            password: 34567890,
            discriminator: 2976,
        };
        let pairing_code = comm_data.compute_pairing_code();
        assert_eq!(pairing_code, "26318621095");
    }
}

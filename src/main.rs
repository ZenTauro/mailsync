// This file is part of MailSync.
//
// MailSync is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// MailSync is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public
// License along with MailSync.
// If not, see <https://www.gnu.org/licenses/>.

pub(crate) mod parser;

use nom::{IResult, bytes::complete::take};
use async_std::prelude::*;
use async_imap::error::Result;

fn main() {
    println!("Hello, world!");
}

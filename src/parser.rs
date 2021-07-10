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

use nom::bytes::complete::{tag, take_while, escaped};
use nom::character::complete::{alpha1, multispace0};
use nom::character::streaming::one_of;
use nom::branch::alt;
use nom::sequence::{delimited, preceded};
use nom::IResult;

use std::vec::Vec;

pub type Accounts = Vec<Account>;
pub type StrLike<'a> = &'a str;

pub enum CreateType {
    Both,
}

pub struct Account {
    name: String,
    host: String,
    user: String,
    pass_cmd: String,
    ssl_type: String,
    cert_file: String,
    imap_store: IMAPStore,
    maildir_store: MaildirStore,
    channel: Channel,
}

pub struct IMAPStore {
    name: String,
    account: String,
}

pub struct MaildirStore {
    name: String,
    subfolders: String,
    path: String,
    inbox: String,
}

pub struct Channel {
    name: String,
    far: String,
    near: String,
    patterns: Vec<String>,
    create: CreateType,
    sync_state: String,
}

/// A combinator that takes a parser `inner` and produces a parser
/// that also consumes both leading and trailing whitespace, returning
/// the output of `inner`.
fn ws<'a, F: 'a, O>(
    inner: F,
) -> impl FnMut(&'a str) -> IResult<&'a str, O>
where
    F: Fn(&'a str) -> IResult<&'a str, O>,
{
    delimited(multispace0, inner, multispace0)
}

/// Parses a comment
fn comment(s: &str)  -> IResult<&str, &str> {
    delimited(preceded(multispace0, tag("#")), take_while(|c: char| c != '\n'), tag("\n"))(s)
}

/// Parses the end of declaration delimiter
fn eol(s: &str) -> IResult<&str, &str> {
    alt((comment, tag("\n")))(s)
}

/// Parses the declaration of a key
fn key<'a>(
    inner: &'static str,
) -> impl FnMut(&'a str) -> IResult<&'a str, &'a str>
{
    ws(tag(inner))
}

fn normal_argument(s: &str) -> IResult<&str, &str> {
    take_while(|c: char| c != '\n' && c != '#')(s)
}

/// Parses a key value line
fn key_value<'a, F: 'a, O>(
    key_name: &'static str,
    inner: F,
) -> impl FnMut(&'a str) -> IResult<&'a str, O>
where
    F: Fn(&'a str) -> IResult<&'a str, O>,
{
    delimited(key(key_name), inner, alt((comment, tag("\n"))))
}

/// Parses line into account name
fn account_name(i: StrLike) -> IResult<StrLike, StrLike> {
    key_value("IMAPAccount", alpha1)(i)
}

fn host_name(i: StrLike) -> IResult<StrLike, StrLike> {
    key_value("Host", take_while(|c: char| !c.is_whitespace()))(i)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parses_comment_1() {
        let input = "# this is a comment\n";

        match comment(input) {
            Ok((rest, parsed)) => {
                assert_eq!(parsed, " this is a comment");
                assert_eq!(rest, "");
            }
            Err(e) => {
                panic!("{}", e);
            }
        }
    }

    #[test]
    fn parses_comment_2() {
        let input = "    # this is also a comment\n";

        match comment(input) {
            Ok((rest, parsed)) => {
                assert_eq!(parsed, " this is also a comment");
                assert_eq!(rest, "");
            }
            Err(e) => {
                panic!("{}", e);
            }
        }
    }

    #[test]
    fn parses_key() {
        let input = "Key value";

        match key("Key")(input) {
            Ok((rest, parsed)) => {
                assert_eq!(parsed, "Key");
                assert_eq!(rest, "value");
            }
            Err(e) => {
                panic!("{}", e);
            }
        }
    }

    #[test]
    fn parses_normal_argument_1() {
        let input = "value\n";

        match normal_argument(input) {
            Ok((rest, parsed)) => {
                assert_eq!(parsed, "value");
                assert_eq!(rest, "\n");
            }
            Err(e) => {
                panic!("{}", e);
            }
        }
    }

    #[test]
    fn parses_normal_argument_2() {
        let input = "value \n";

        match normal_argument(input) {
            Ok((rest, parsed)) => {
                assert_eq!(parsed, "value ");
                assert_eq!(rest, "\n");
            }
            Err(e) => {
                panic!("{}", e);
            }
        }
    }

    #[test]
    fn parses_normal_argument_3() {
        let input = "value # this is a comment\n";

        match normal_argument(input) {
            Ok((rest, parsed)) => {
                assert_eq!(parsed, "value ");
                assert_eq!(rest, "# this is a comment\n");
            }
            Err(e) => {
                panic!("{}", e);
            }
        }
    }

    #[test]
    fn parses_key_value() {
        let input = "Key value # this is a comment\n";

        match key_value("Key", normal_argument)(input) {
            Ok((rest, parsed)) => {
                assert_eq!(parsed, "value ");
                assert_eq!(rest, "");
            }
            Err(e) => {
                panic!("{}", e);
            }
        }
    }

    #[test]
    fn parses_account_name() {
        let input = "IMAPAccount gmail # Another comment\n";

        match account_name(input) {
            Ok((rest, parsed)) => {
                assert_eq!(parsed, "gmail");
                assert_eq!(rest, "");
            }
            Err(e) => {
                panic!("{}", e);
            }
        }
    }

    #[test]
    fn parses_host_name() {
        let input = "Host some.sample@mail.gmail.com # Another comment\n";

        match host_name(input) {
            Ok((rest, parsed)) => {
                assert_eq!(parsed, "some.sample@mail.gmail.com");
                assert_eq!(rest, "");
            }
            Err(e) => {
                panic!("{}", e);
            }
        }
    }
}

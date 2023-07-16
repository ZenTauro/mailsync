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

use nom::bytes::complete::{tag, take_while, take_while1, escaped};
use nom::character::complete::{alpha1, one_of};
use nom::branch::alt;
use nom::sequence::{delimited, preceded, tuple, pair, terminated};
use nom::IResult;
use nom::combinator::map;
use nom::multi::many0;
use nom::error::{ParseError, VerboseError, convert_error};

use std::str::ParseBoolError;
use std::vec::Vec;

pub type Accounts = Vec<Account>;
pub type StrLike<'a> = &'a str;

#[derive(Debug, PartialEq, Eq)]
pub enum CreateType {
    Both,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SSLType {
    IMAPS
}

#[derive(Debug, PartialEq, Eq)]
pub struct Account {
    name: String,
    host: String,
    user: String,
    pass_cmd: String,
    ssl_type: SSLType,
    cert_file: String,
    // imap_store: IMAPStore,
    // maildir_store: MaildirStore,
    // channel: Channel,
}

#[derive(Debug, PartialEq, Eq)]
pub struct IMAPStore {
    name: String,
    account: String,
}

#[derive(Debug, PartialEq, Eq)]
pub struct MaildirStore {
    name: String,
    subfolders: String,
    path: String,
    inbox: String,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Channel {
    name: String,
    far: String,
    near: String,
    patterns: Vec<String>,
    create: CreateType,
    sync_state: String,
}

///
pub enum ConfigExpr {
    Account(AccountExpr),
    IMAPStore(IMAPStoreExpr),
    MaildirStore(MaildirStoreExpr),
    Channel(ChannelExpr)
}

/// AST types
#[derive(Debug, PartialEq, Eq)]
pub enum AccountExpr {
    NameDeclaration(String),
    Host(String),
    User(String),
    PassCmd(String),
    SSLType(SSLType),
    CertificateFile(String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum IMAPStoreExpr {
    NameDeclaration(String),
    Account(String)
}

#[derive(Debug, PartialEq, Eq)]
pub enum MaildirStoreExpr {
    NameDeclaration(String),
    Subfolders(SubfoldersType),
    Path(String),
    Inbox(String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum SubfoldersType {
    Verbatim
}

#[derive(Debug, PartialEq, Eq)]
pub enum ChannelExpr {
    NameDeclaration(String),
    Far(String),
    Near(String),
    Patterns(Vec<String>),
    Create(CreateType),
    SyncState(String),
}

pub type AST = Vec<AccountExpr>;

/// Parses the end of declaration delimiter
fn ws_nonl<'a, E: ParseError<&'a str>>(s: &'a str) -> IResult<&str, Vec<&str>, E> {
    many0(alt((tag(" "), tag("\t"))))(s)
}

/// A combinator that takes a parser `inner` and produces a parser
/// that also consumes both leading and trailing whitespace, returning
/// the output of `inner`.
fn ws<'a, F: 'a, O, E: ParseError<&'a str>>(
    inner: F,
) -> impl FnMut(&'a str) -> IResult<&'a str, O, E>
where
    F: Fn(&'a str) -> IResult<&'a str, O, E>,
{
    delimited(ws_nonl, inner, ws_nonl)
}

/// Parses a comment
fn comment<'a, E: ParseError<&'a str>>(s: &'a str)  -> IResult<&str, &str, E> {
    delimited(preceded(ws_nonl, tag("#")), take_while(|c: char| c != '\n'), tag("\n"))(s)
}

/// Parses the end of declaration delimiter
fn eol<'a, E: ParseError<&'a str>>(s: &'a str) -> IResult<&str, &str, E> {
    alt((comment, preceded(ws_nonl, tag("\n"))))(s)
}

/// Parses the declaration of a key
fn key<'a, E: ParseError<&'a str> + 'a>(
    inner: &'static str,
) -> impl FnMut(&'a str) -> IResult<&'a str, &'a str, E>
{
    ws(tag(inner))
}

fn normal_argument<'a, E: ParseError<&'a str>>(s: &'a str) -> IResult<&str, &str, E> {
    take_while(|c: char| c != '\n' && c != '#')(s)
}

/// Parses a key value line
fn key_value<'a, F: 'a, O, E: ParseError<&'a str> + 'a>(
    key_name: &'static str,
    inner: F,
) -> impl FnMut(&'a str) -> IResult<&'a str, O, E>
where
    F: Fn(&'a str) -> IResult<&'a str, O, E>,
{
    delimited(key(key_name), inner, alt((comment, preceded(ws_nonl, tag("\n")))))
}

/// Parses an escaped string, captures the inside of the quote
/// delimited string:
///
/// ```
/// let Ok((_, res)) = string_parser("\"the string\"");
/// assert_eq!(res, "the string");
/// ```
pub fn string_parser<'a, E: ParseError<&'a str>>(i: StrLike<'a>) -> IResult<StrLike<'a>, StrLike, E> {
    delimited(
        tag("\""),
        escaped(
            take_while1(|c: char| c != '\n' && c != '\\' && c != '"'),
            '\\',
            one_of(r#"\"n"#)
        ),
        tag("\"")
    )(i)
}

/// Parses line into account name
fn account_name<'a, E: ParseError<&'a str> + 'a>(i: &'a str) -> IResult<StrLike, AccountExpr, E> {
    map(
        key_value("IMAPAccount", alpha1),
        |x| AccountExpr::NameDeclaration(x.to_owned())
    )(i)
}

/// Parses host name line
fn host_name<'a, E: ParseError<&'a str> + 'a>(i: &'a str) -> IResult<StrLike, AccountExpr, E> {
    map(
        key_value("Host", take_while(|c: char| !c.is_whitespace())),
        |x| AccountExpr::Host(x.to_owned())
    )(i)
}

/// Parses user name line
fn user_name<'a, E: ParseError<&'a str> + 'a>(i: &'a str) -> IResult<StrLike, AccountExpr, E> {
    map(
        key_value("User", take_while(|c: char| !c.is_whitespace())),
        |x| AccountExpr::User(x.to_owned())
    )(i)
}

/// Parses the PassCmd line
fn pass_cmd<'a, E: ParseError<&'a str> + 'a>(i: &'a str) -> IResult<StrLike, AccountExpr, E> {
    map(
        key_value("PassCmd", string_parser),
        |x| AccountExpr::PassCmd(x.to_owned())
    )(i)
}

/// Parses the SSLType line
fn ssl_type<'a, E: ParseError<&'a str> + 'a>(i: &'a str) -> IResult<StrLike, AccountExpr, E> {
    map(
        key_value("SSLType", normal_argument),
        |x| {
            let t = match x.trim() {
                "IMAPS" => SSLType::IMAPS,
                     s  => unimplemented!("Find how to throw and error but keep parsing: {}", s)
            };
            AccountExpr::SSLType(t)
        }
    )(i)
}

/// Parses the CertificateFile line
// TODO: Use a better parser for the argument of Certificate file
//       instead of normal_argument
fn certificate_file<'a, E: ParseError<&'a str> + 'a>(i: &'a str) -> IResult<StrLike, AccountExpr, E> {
    map(
        key_value("CertificateFile", normal_argument),
        |x| AccountExpr::CertificateFile(x.trim().to_owned())
    )(i)
}

/// Parses the IMAPStore line
fn imap_store_name<'a, E: ParseError<&'a str> + 'a>(i: StrLike<'a>) -> IResult<StrLike<'a>, IMAPStoreExpr, E> {
    map(
        key_value("IMAPStore", normal_argument),
        |x| IMAPStoreExpr::NameDeclaration(x.trim().to_owned())
    )(i)
}

/// Parses the Account line
fn account<'a, E: ParseError<&'a str> + 'a>(i: &'a str) -> IResult<StrLike, IMAPStoreExpr, E> {
    map(
        key_value("Account", normal_argument),
        |x| IMAPStoreExpr::Account(x.trim().to_owned())
    )(i)
}

/// Parses an IMAPStore block
fn imap_store_block<'a, E: ParseError<&'a str> + 'a>(i: &'a str) -> IResult<&'a str, IMAPStore, E> {
    map(
        terminated(tuple((imap_store_name, account)), tag("\n")),
        |x| {
            match x {
                (IMAPStoreExpr::NameDeclaration(store_name), IMAPStoreExpr::Account(acc)) =>
                    IMAPStore {name: store_name, account: acc},
                _ => panic!(
                    concat!(
                        "This should never happen since",
                        "imap_store_name and account always return",
                        "the specified enum variants"
                    )
                )
            }
        }
    )(i)
}

fn imap_account_lines_block<'a, E: ParseError<&'a str> + 'a>(i: StrLike<'a>) -> IResult<StrLike<'a>, Vec<AccountExpr>, E> {
    many0(alt((
        host_name,
        user_name,
        pass_cmd,
        ssl_type,
        certificate_file
    )))(i)
}

/// Parses an IMAPAccount block
pub fn imap_account_block<'a, E: ParseError<&'a str> + 'a>(i: StrLike<'a>) -> IResult<StrLike<'a>, Account, E> {
    let block_parser = tuple((account_name, imap_account_lines_block, tag("\n")));

    map(block_parser, |x| {
        match x {
            (AccountExpr::NameDeclaration(acc_name), params, _) => {
                let mut host_v = String::new();
                let mut user_v = String::new();
                let mut pass_cmd_v = String::new();
                let mut ssl_type_v = SSLType::IMAPS;
                let mut cert_file_v = String::new();

                for param in params {
                    match param {
                        AccountExpr::Host(v) => {host_v = v;},
                        AccountExpr::User(v) => {user_v = v;},
                        AccountExpr::PassCmd(v) => {pass_cmd_v = v;},
                        AccountExpr::SSLType(v) => {ssl_type_v = v;},
                        AccountExpr::CertificateFile(v) => {cert_file_v = v;},
                        AccountExpr::NameDeclaration(_) => {panic!("This should not happen")},
                    }
                }

                Account {
                    name: acc_name.to_string(),
                    host: host_v,
                    user: user_v,
                    pass_cmd: pass_cmd_v,
                    ssl_type: ssl_type_v,
                    cert_file: cert_file_v,
                }
            }
            _ => panic!("This should never happen since it can only succeed if the form is the name declaration first and the others later")
        }
    })(i)
}

#[cfg(test)]
mod test {
    use nom::Finish;

    use super::*;

    fn simple_parser_tester<'a, P, R>(
        input: &'a str,
        parser: P,
        expected: R,
    )
        where P: Fn(&'a str) -> IResult<&'a str, R>,
              R: std::fmt::Debug + Eq
    {
        let (rest, parsed) = parser(input).unwrap();

        assert_eq!(parsed, expected);
        assert_eq!(rest, "");
    }

    #[test]
    fn parses_comment_1() {
        let parser = comment;

        let input = "# this is a comment\n";
        let expected = " this is a comment";

        simple_parser_tester(input, parser, expected)
    }

    #[test]
    fn parses_comment_2() {
        let parser = comment;

        let input = "    # this is also a comment\n";
        let expected = " this is also a comment";

        simple_parser_tester(input, parser, expected)
    }

    #[test]
    fn parses_comment_3() {
        let parser = comment;

        let input = "    #\n";
        let expected = "";

        simple_parser_tester(input, parser, expected)
    }

    #[test]
    fn parses_key() {
        let input = "Key value";

        match key::<VerboseError<&str>>("Key")(input) {
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

        match normal_argument::<VerboseError<&str>>(input) {
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

        match normal_argument::<VerboseError<&str>>(input) {
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

        match normal_argument::<VerboseError<&str>>(input) {
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

        match key_value::<_, &str, VerboseError<&str>>("Key", normal_argument)(input) {
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
    fn parses_escaped_string() {
        let input = r#""this escaped string contains a \" symbol" this should be out of the parsed part"#;

        match string_parser::<VerboseError<&str>>(input) {
            Ok((rest, parsed)) => {
                assert_eq!(parsed, r#"this escaped string contains a \" symbol"#);
                assert_eq!(rest, " this should be out of the parsed part");
            }
            Err(e) => {
                panic!("{}", e);
            }
        }
    }

    #[test]
    fn parses_imap_account_name() {
        let parser = account_name;

        let input = "IMAPAccount mail # Another comment\n";
        let expected = AccountExpr::NameDeclaration("mail".to_string());

        simple_parser_tester(input, parser, expected)
    }

    #[test]
    fn parses_host_name() {
        let parser = host_name;

        let input = "Host some.sample@mail.gmail.com # Another comment\n";
        let expected = AccountExpr::Host("some.sample@mail.gmail.com".to_string());

        simple_parser_tester(input, parser, expected)
    }

    #[test]
    fn parses_user_name() {
        let parser = user_name;

        let input = "User some.sample@mail.gmail.com # Another comment\n";
        let expected = AccountExpr::User("some.sample@mail.gmail.com".to_string());

        simple_parser_tester(input, parser, expected)
    }

    #[test]
    fn parses_pass_cmd() {
        let parser = pass_cmd;

        let input = "PassCmd \"get_password -a \\\"some.sample@mail.com\\\"\"  # Another comment\n";
        let expected = AccountExpr::PassCmd("get_password -a \\\"some.sample@mail.com\\\"".to_string());

        simple_parser_tester(input, parser, expected)
    }


    #[test]
    fn parses_ssl_type() {
        let parser = ssl_type;

        let input = "SSLType IMAPS  # Another comment\n";
        let expected = AccountExpr::SSLType(SSLType::IMAPS);

        simple_parser_tester(input, parser, expected);
    }

    #[test]
    fn parses_certificate_file() {
        let parser = certificate_file;

        let input = "CertificateFile /some/random/file  # Another comment\n";
        let expected = AccountExpr::CertificateFile("/some/random/file".to_owned());

        simple_parser_tester(input, parser, expected)
    }

    #[test]
    fn parses_imap_store_name() {
        let parser = imap_store_name;

        let input = "IMAPStore mail-remote  # Another comment\n";
        let expected = IMAPStoreExpr::NameDeclaration("mail-remote".to_owned());

        simple_parser_tester(input, parser, expected)
    }

    #[test]
    fn parses_account_name() {
        let parser = account;

        let input = "Account mail  # Another comment\n";
        let expected = IMAPStoreExpr::Account("mail".to_owned());

        simple_parser_tester(input, parser, expected)
    }

    #[test]
    fn parses_imap_store_block() {
        let parser = imap_store_block;

        let input = concat!(
            "IMAPStore mail-remote  # Another comment\n",
            "Account mail  # Another comment\n",
            "\n"
        );
        let expected = IMAPStore {
            name: "mail-remote".to_owned(),
            account: "mail".to_owned()
        };

        simple_parser_tester(input, parser, expected)
    }

    #[test]
    fn block_test() {
        let mut imap_account_lines = many0(
            alt((
                host_name::<VerboseError<&str>>,
                user_name,
                pass_cmd,
                ssl_type,
                certificate_file
            )));

        let input = concat!(
            "Host imap.mail.com   # A comment\n",
            "User example@mail.com   # A comment\n",
            "PassCmd \"get_pass 'example@mail.com'\"   # A comment\n",
            "SSLType IMAPS #\n",
            "CertificateFile /etc/ssl/certs/ca-certificates.crt # comt\n",
        );

        let res = imap_account_lines(input);
        match res {
            Ok((a, _)) => assert_eq!(a, ""),
            Err(e) => panic!("{}", e)
        }
    }

    #[test]
    fn block_test_named() {
        let input = concat!(
            "Host imap.mail.com   # A comment\n",
            "User example@mail.com   # A comment\n",
            "PassCmd \"get_pass 'example@mail.com'\"   # A comment\n",
            "SSLType IMAPS #\n",
            "CertificateFile /etc/ssl/certs/ca-certificates.crt # comt\n",
        );

        let res = imap_account_lines_block::<VerboseError<&str>>(input);
        match res {
            Ok((a, _)) => assert_eq!(a, ""),
            Err(e) => panic!("{}", e)
        }
    }

    #[test]
    fn parses_imap_account_block() {
        let input = concat!(
            "IMAPAccount mail\n",
            "Host imap.mail.com   # A comment\n",
            "User example@mail.com   # A comment\n",
            "PassCmd \"get_pass 'example@mail.com'\"   # A comment\n",
            "SSLType IMAPS #\n",
            "CertificateFile /etc/ssl/certs/ca-certificates.crt # comt\n",
            "\n"
        );
        let expected = Account {
            name: "mail".to_owned(),
            host: "imap.mail.com".to_owned(),
            user: "example@mail.com".to_owned(),
            pass_cmd: "get_pass 'example@mail.com'".to_owned(),
            ssl_type: SSLType::IMAPS,
            cert_file: "/etc/ssl/certs/ca-certificates.crt".to_owned()
        };

        {
            let expected = expected;
            match imap_account_block::<VerboseError<&str>>(input).finish() {
                Ok((rest, parsed)) => {
                    assert_eq!(parsed, expected);
                    assert_eq!(rest, "");
                }
                Err(e) => panic!("panic here: {:#?}", e),
            }
        }
    }
}

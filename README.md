# certificate_info - Command Line SSL Certificate Information Tool

certificate_info is a command line tool developed in Rust for fetching and displaying SSL certificate information for a given domain. It provides details such as certificate validity, issuer information, and public key hash.

## Usage

```bash
certinfo [OPTIONS] <DOMAIN>
```

### Options

- `-d, --debug` : provide domain for which the certificate information is needed.
- `-h, --help`  : Display help information.

### Example

```bash
certinfo -d example.com
```

## Building from Source

CertInfo is written in Rust. Make sure you have Rust and Cargo installed on your system.

```bash
git clone https://github.com/username/certinfo.git
cd certinfo
cargo build --release
```

## Running

After building the tool, you can run it using the following command:

```bash
./target/release/certinfo [OPTIONS] <DOMAIN>
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.


## Acknowledgments

- The Rust Community
- OpenSSL Library

## Disclaimer

This tool is provided "as is" without warranty of any kind. Use at your own risk.

## Author

[Ishan Malviya](https://github.com/Philosopher-G33k)

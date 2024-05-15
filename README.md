<a name="readme-top"></a>

[Contributors][contributors-url]
[Issues][issues-url]

<!-- PROJECT INFO -->
<h3 align="center">Bitcoin K256</h3>

  <p align="center">
    This is a fork of the official Bitcoin Rust library. The secp256k1 crate is swapped out for the k256 crate
    to remove the dependance on FFI calls to the C library in the official bitcoin library.
    This enables the use of this library on architectures that do not natively support the C compiler such as Risc0.
    <br />
    ·
    <a href="https://github.com/leonardchinonso/bitcoin-k256/issues/new?labels=bug&template=bug-report---.md">Report Bug</a>
    ·
    <a href="https://github.com/leonardchinonso/bitcoin-k256/issues/new?labels=enhancement&template=feature-request---.md">Request Feature</a>
  </p>
</div>



<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#acknowledgments">Acknowledgments</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project

<p align="right">(<a href="#readme-top">back to top</a>)</p>



### Built With

* [Rust][Rust-url]

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- GETTING STARTED -->
## Getting Started

Check out the [official bitcoin rust library](https://github.com/rust-bitcoin/rust-bitcoin)

### Prerequisites

Check out the [official bitcoin rust library](https://github.com/rust-bitcoin/rust-bitcoin)

### Installation

Add to your Cargo.toml file



<!-- USAGE EXAMPLES -->
## Usage

Check out the [official bitcoin rust library](https://github.com/rust-bitcoin/rust-bitcoin)



<!-- ROADMAP -->
## Roadmap

See the [open issues](https://github.com/leonardchinonso/bitcoin-k256/issues) for a full list of proposed features (and known issues).

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- CONTRIBUTING -->
## Contributing

Open a Pull Request with your suggested feature or bug fix

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE.txt` for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- ACKNOWLEDGMENTS -->
## Acknowledgments

* [The official bitcoin rust library](https://github.com/rust-bitcoin/rust-bitcoin)

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- MARKDOWN LINKS & IMAGES -->
[contributors-url]: https://github.com/leonardchinonso/bitcoin-k256/graphs/contributors
[issues-url]: https://github.com/leonardchinonso/bitcoin-k256/issues
[Rust-url]: https://www.rust-lang.org/